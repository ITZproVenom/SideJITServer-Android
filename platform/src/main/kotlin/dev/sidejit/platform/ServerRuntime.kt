package dev.sidejit.platform

import android.content.Context
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.core.mdns.MdnsResponder
import dev.sidejit.core.mdns.ServiceRegistration
import dev.sidejit.core.net.Interfaces
import dev.sidejit.pairing.HostIdentity
import dev.sidejit.pairing.PairableHostListener
import dev.sidejit.pairing.VerifiedSession
import dev.sidejit.server.LocalHttpApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * The server, independent of anything on screen.
 *
 * The television this is meant to run on may have no working display at all,
 * so nothing here may depend on an Activity existing, being visible, or ever
 * having been visible. The foreground service owns this object; the interface
 * only reads [state].
 */
class ServerRuntime private constructor(private val context: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val started = AtomicBoolean(false)

    private val _state = MutableStateFlow(ServerState())
    val state: StateFlow<ServerState> = _state.asStateFlow()

    private var identity: HostIdentity? = null
    private var listener: PairableHostListener? = null
    private var responder: MdnsResponder? = null
    private var httpApi: LocalHttpApi? = null
    private var lease: MulticastLease? = null
    private var watcher: NetworkWatcher? = null
    private var lastSignature: String = ""
    private val lastVerified = AtomicReference<VerifiedSession?>(null)

    fun start() {
        if (!started.compareAndSet(false, true)) return
        Log.i(LogTag.SERVER, "runtime starting")
        _state.update { it.copy(wifi = Stage("Wi-Fi", StageStatus.RUNNING, "looking for an address")) }
        val store = VaultPairingStore(context)
        val host = IdentityStorage.loadOrCreate(context)
        identity = host
        _state.update {
            it.copy(
                device = if (store.all().isEmpty()) {
                    Stage("Paired iOS device", StageStatus.IDLE, "none paired yet")
                } else {
                    Stage(
                        "Paired iOS device",
                        StageStatus.IDLE,
                        store.all().joinToString { record -> record.peer.name } + " (re-verify on connect)",
                    )
                },
                tunnel = Stage(
                    "CoreDevice tunnel",
                    StageStatus.IDLE,
                    "code present; opens after pair-verify + createListener",
                ),
                developerServices = Stage(
                    "Developer services",
                    StageStatus.IDLE,
                    "RSD/DVT/GDB code present; needs live tunnel",
                ),
                jit = Stage(
                    "JIT",
                    StageStatus.IDLE,
                    "orchestration present; needs paired device + live path",
                ),
            )
        }

        val pairing = PairableHostListener(host, store)
        pairing.onSetupCode = { code -> _state.update { it.copy(setupCode = code) } }
        pairing.onPaired = { record ->
            _state.update {
                it.copy(
                    device = Stage("Paired iOS device", StageStatus.READY, record.peer.name),
                    pairing = Stage("Wireless pairing", StageStatus.READY, "waiting for a device"),
                )
            }
        }
        pairing.onVerified = { session ->
            lastVerified.set(session)
            _state.update {
                it.copy(
                    device = Stage(
                        "Paired iOS device",
                        StageStatus.READY,
                        "${session.record.peer.name} (verified)",
                    ),
                    tunnel = Stage(
                        "CoreDevice tunnel",
                        StageStatus.IDLE,
                        "verified session ready; createListener still needs device",
                    ),
                )
            }
            Log.i(LogTag.SERVER, "pair-verify succeeded for ${session.record.peer.name}")
        }
        pairing.onFailure = { reason ->
            _state.update {
                it.copy(pairing = Stage("Wireless pairing", StageStatus.RUNNING, "last attempt failed: $reason"))
            }
        }
        listener = pairing

        val port = try {
            pairing.start()
        } catch (failure: Exception) {
            Log.e(LogTag.SERVER, "the pairing listener could not start", failure)
            _state.update {
                it.copy(pairing = Stage("Wireless pairing", StageStatus.FAILED, failure.describe()))
            }
            return
        }
        _state.update {
            it.copy(pairing = Stage("Wireless pairing", StageStatus.READY, "listening on port $port"))
        }

        startHttpApi()

        lease = MulticastLease(context).apply { acquire() }
        publishAddresses()
        startResponder(host, port)

        watcher = NetworkWatcher(context) { onNetworkChanged(host, port) }.also { it.start() }
    }

    private fun startHttpApi() {
        val candidates = listOf(8080, 8081, 8090, 0)
        var lastError: Exception? = null
        for (p in candidates) {
            try {
                val api = LocalHttpApi(port = p)
                api.start()
                httpApi = api
                val bound = api.boundPort
                _state.update {
                    it.copy(
                        api = Stage(
                            "Local HTTP API",
                            StageStatus.READY,
                            "http://0.0.0.0:$bound  (SideStore: ANDROID_IP:$bound)",
                        ),
                    )
                }
                Log.i(LogTag.SERVER, "HTTP API listening on $bound")
                return
            } catch (e: Exception) {
                lastError = e
                Log.w(LogTag.SERVER, "HTTP bind failed on $p: ${e.message}")
            }
        }
        _state.update {
            it.copy(
                api = Stage(
                    "Local HTTP API",
                    StageStatus.FAILED,
                    lastError?.describe() ?: "could not bind",
                ),
            )
        }
    }

    private fun startResponder(host: HostIdentity, port: Int) {
        val pairable = ServiceRegistration(
            instanceName = host.identifier,
            serviceType = PAIRABLE_HOST_SERVICE_TYPE,
            hostName = host.mdnsHostName,
            port = port,
            txtRecords = host.mdnsTxtRecords(pinless = false),
        )
        val httpPort = httpApi?.boundPort ?: -1
        val services = mutableListOf(pairable)
        if (httpPort > 0) {
            services += ServiceRegistration(
                instanceName = "SideJITServer",
                serviceType = HTTP_SERVICE_TYPE,
                hostName = host.mdnsHostName,
                port = httpPort,
                txtRecords = mapOf("path" to "/", "version" to "0.1.0"),
            )
        }
        try {
            responder = MdnsResponder(services).also { it.start() }
            _state.update {
                it.copy(
                    mdns = Stage(
                        "mDNS advertisement",
                        StageStatus.READY,
                        "$PAIRABLE_HOST_SERVICE_TYPE on $port" +
                            if (httpPort > 0) "; $HTTP_SERVICE_TYPE on $httpPort" else "",
                    ),
                )
            }
        } catch (failure: Exception) {
            Log.e(LogTag.SERVER, "the advertisement could not start", failure)
            _state.update {
                it.copy(mdns = Stage("mDNS advertisement", StageStatus.FAILED, failure.describe()))
            }
        }
    }

    private fun publishAddresses() {
        val addresses = Interfaces.preferredAddresses().map { it.literal }
        lastSignature = Interfaces.signature()
        _state.update {
            it.copy(
                addresses = addresses,
                wifi = if (addresses.isEmpty()) {
                    Stage("Wi-Fi", StageStatus.FAILED, "no network address")
                } else {
                    Stage("Wi-Fi", StageStatus.READY, addresses.first())
                },
            )
        }
    }

    private fun onNetworkChanged(host: HostIdentity, port: Int) {
        val signature = Interfaces.signature()
        if (signature == lastSignature) return
        Log.i(LogTag.SERVER, "the network changed, renewing the advertisement")
        publishAddresses()
        val current = responder
        if (current == null) {
            startResponder(host, port)
        } else {
            runCatching { current.stop() }
            startResponder(host, port)
        }
    }

    fun stop() {
        if (!started.compareAndSet(true, false)) return
        Log.i(LogTag.SERVER, "runtime stopping")
        watcher?.stop()
        watcher = null
        runCatching { responder?.stop() }
        responder = null
        runCatching { httpApi?.stop() }
        httpApi = null
        listener?.stop()
        listener = null
        lease?.release()
        lease = null
        identity = null
        lastVerified.set(null)
        _state.value = ServerState()
    }

    fun lastVerifiedSession(): VerifiedSession? = lastVerified.get()

    internal fun update(transform: (ServerState) -> ServerState) = _state.update(transform)

    companion object {
        const val PAIRABLE_HOST_SERVICE_TYPE: String = "_remotepairing-pairable-host._tcp"
        const val HTTP_SERVICE_TYPE: String = "_http._tcp"

        @Volatile
        private var instance: ServerRuntime? = null

        fun get(context: Context): ServerRuntime =
            instance ?: synchronized(this) {
                instance ?: ServerRuntime(context.applicationContext).also { instance = it }
            }
    }
}
