package dev.sidejit.platform

import android.content.Context
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.core.mdns.MdnsResponder
import dev.sidejit.core.mdns.ServiceRegistration
import dev.sidejit.core.net.Interfaces
import dev.sidejit.jit.JitEngine
import dev.sidejit.pairing.HostIdentity
import dev.sidejit.pairing.PairableHostListener
import dev.sidejit.pairing.PairVerifyClient
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
    private val lastPeerHost = AtomicReference<String?>(null)
    private val lastListenerPort = AtomicReference<Int?>(null)

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
                tunnel = Stage("CoreDevice tunnel", StageStatus.IDLE, "waiting for pair-verify + createListener"),
                developerServices = Stage("Developer services", StageStatus.IDLE, "needs live tunnel"),
                jit = Stage("JIT", StageStatus.IDLE, "needs live tunnel + DVT/GDB"),
            )
        }

        val pairing = PairableHostListener(host, store)
        pairing.onSetupCode = { code -> _state.update { it.copy(setupCode = code) } }
        pairing.onPaired = { record, peerHost ->
            lastPeerHost.set(peerHost)
            _state.update {
                it.copy(
                    device = Stage("Paired iOS device", StageStatus.READY, "${record.peer.name} @ $peerHost"),
                    pairing = Stage("Wireless pairing", StageStatus.READY, "pair-setup complete; starting host-side pair-verify"),
                    tunnel = Stage("CoreDevice tunnel", StageStatus.RUNNING, "connecting to iPhone _remotepairing._tcp"),
                )
            }
            scope.launch {
                try {
                    val result = PairVerifyClient.connect(
                        host = peerHost,
                        port = REMOTE_PAIRING_DEFAULT_PORT,
                        identity = host,
                        record = record,
                    )
                    lastVerified.set(result.session)
                    lastPeerHost.set(peerHost)
                    lastListenerPort.set(result.listenerPort)
                    _state.update {
                        it.copy(
                            device = Stage(
                                "Paired iOS device",
                                StageStatus.READY,
                                "${record.peer.name} (verified) @ $peerHost",
                            ),
                            tunnel = Stage(
                                "CoreDevice tunnel",
                                StageStatus.READY,
                                "createListener port ${result.listenerPort} on $peerHost",
                            ),
                            jit = Stage("JIT", StageStatus.IDLE, "ready to attempt /launch"),
                        )
                    }
                    Log.i(LogTag.SERVER, "host-side pair-verify + createListener succeeded for ${record.peer.name}")
                } catch (failure: Exception) {
                    _state.update {
                        it.copy(
                            tunnel = Stage(
                                "CoreDevice tunnel",
                                StageStatus.FAILED,
                                "host-side pair-verify failed: ${failure.message ?: failure.javaClass.simpleName}",
                            ),
                        )
                    }
                    Log.e(LogTag.SERVER, "host-side pair-verify failed for ${record.peer.name}", failure)
                }
            }
        }
        pairing.onVerified = { session, peerHost ->
            lastVerified.set(session)
            lastPeerHost.set(peerHost)
            _state.update {
                it.copy(
                    device = Stage(
                        "Paired iOS device",
                        StageStatus.READY,
                        "${session.record.peer.name} (verified) @ $peerHost",
                    ),
                    tunnel = Stage(
                        "CoreDevice tunnel",
                        StageStatus.RUNNING,
                        "verified; requesting createListener\u2026",
                    ),
                )
            }
            Log.i(LogTag.SERVER, "pair-verify ok ${session.record.peer.name} from $peerHost")
        }
        pairing.onTunnelListener = { peerHost, listenerPort ->
            lastPeerHost.set(peerHost)
            lastListenerPort.set(listenerPort)
            _state.update {
                it.copy(
                    tunnel = Stage(
                        "CoreDevice tunnel",
                        StageStatus.READY,
                        "createListener port $listenerPort on $peerHost",
                    ),
                    jit = Stage("JIT", StageStatus.IDLE, "ready to attempt /launch"),
                )
            }
            Log.i(LogTag.SERVER, "tunnel listener $peerHost:$listenerPort")
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
                val api = LocalHttpApi(
                    port = p,
                    statusProvider = { buildStatusJson() },
                    launchHandler = { bundleId -> handleLaunch(bundleId) },
                )
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
            it.copy(api = Stage("Local HTTP API", StageStatus.FAILED, lastError?.describe() ?: "could not bind"))
        }
    }

    private fun buildStatusJson(): String {
        val session = lastVerified.get()
        val peer = lastPeerHost.get()
        val listenerPort = lastListenerPort.get()
        val paired = session != null
        val jit = when {
            session != null && listenerPort != null -> "ready_to_attempt"
            session != null -> "paired_need_listener"
            else -> "not_ready"
        }
        val device = session?.record?.peer?.name?.let { LocalHttpApi.jsonEscapeStatic(it) } ?: "null"
        val peerJson = peer?.let { LocalHttpApi.jsonEscapeStatic(it) } ?: "null"
        val portJson = listenerPort?.toString() ?: "null"
        val stack = LocalHttpApi.jsonEscapeStatic(JitEngine.describeStack())
        return """{"ok":true,"jit":${LocalHttpApi.jsonEscapeStatic(jit)},"paired":$paired,"device":$device,"peerHost":$peerJson,"listenerPort":$portJson,"version":"0.1.0","stack":$stack}"""
    }

    private fun handleLaunch(bundleId: String): JitEngine.Result {
        val session = lastVerified.get()
            ?: return JitEngine.Result.Failed(
                "no verified session yet \u2014 complete wireless pair (and re-verify) first; bundleId=$bundleId",
            )
        val peer = lastPeerHost.get()
            ?: return JitEngine.Result.Failed(
                "paired (${session.record.peer.name}) but peer IP unknown; pair again; bundleId=$bundleId",
            )
        val listenerPort = lastListenerPort.get()
            ?: return JitEngine.Result.Failed(
                "paired with ${session.record.peer.name} @ $peer but createListener port missing. " +
                    "Re-pair so verify runs again and watch Android logs for createListener. bundleId=$bundleId",
            )
        _state.update {
            it.copy(jit = Stage("JIT", StageStatus.RUNNING, "launch $bundleId via tunnel\u2026"))
        }
        val result = JitEngine.enable(bundleId, session, peer, listenerPort)
        when (result) {
            is JitEngine.Result.Granted ->
                _state.update {
                    it.copy(jit = Stage("JIT", StageStatus.READY, "granted pid=${result.pid} for $bundleId"))
                }
            is JitEngine.Result.Failed ->
                _state.update {
                    it.copy(jit = Stage("JIT", StageStatus.FAILED, result.reason.take(120)))
                }
        }
        return result
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
        runCatching { responder?.stop() }
        startResponder(host, port)
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
        lastPeerHost.set(null)
        lastListenerPort.set(null)
        _state.value = ServerState()
    }

    fun lastVerifiedSession(): VerifiedSession? = lastVerified.get()

    internal fun update(transform: (ServerState) -> ServerState) = _state.update(transform)

    companion object {
        const val PAIRABLE_HOST_SERVICE_TYPE: String = "_remotepairing-pairable-host._tcp"
        const val HTTP_SERVICE_TYPE: String = "_http._tcp"
        const val REMOTE_PAIRING_DEFAULT_PORT: Int = 49152

        @Volatile
        private var instance: ServerRuntime? = null

        fun get(context: Context): ServerRuntime =
            instance ?: synchronized(this) {
                instance ?: ServerRuntime(context.applicationContext).also { instance = it }
            }
    }
}
