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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicBoolean

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
    private var lease: MulticastLease? = null
    private var watcher: NetworkWatcher? = null
    private var lastSignature: String = ""

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
                        store.all().joinToString { record -> record.peer.name },
                    )
                },
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

        lease = MulticastLease(context).apply { acquire() }
        publishAddresses()
        startResponder(host, port)

        watcher = NetworkWatcher(context) { onNetworkChanged(host, port) }.also { it.start() }
    }

    private fun startResponder(host: HostIdentity, port: Int) {
        val service = ServiceRegistration(
            instanceName = host.identifier,
            serviceType = PAIRABLE_HOST_SERVICE_TYPE,
            hostName = host.mdnsHostName,
            port = port,
            txtRecords = host.mdnsTxtRecords(pinless = false),
        )
        try {
            responder = MdnsResponder(listOf(service)).also { it.start() }
            _state.update {
                it.copy(
                    mdns = Stage(
                        "mDNS advertisement",
                        StageStatus.READY,
                        "$PAIRABLE_HOST_SERVICE_TYPE on port $port",
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
        listener?.stop()
        listener = null
        lease?.release()
        lease = null
        identity = null
        _state.value = ServerState()
    }

    internal fun update(transform: (ServerState) -> ServerState) = _state.update(transform)

    companion object {
        /**
         * The service an iOS 26 or later device looks for when it wants to pair into a
         * host without a cable.
         */
        const val PAIRABLE_HOST_SERVICE_TYPE: String = "_remotepairing-pairable-host._tcp"

        @Volatile
        private var instance: ServerRuntime? = null

        fun get(context: Context): ServerRuntime =
            instance ?: synchronized(this) {
                instance ?: ServerRuntime(context.applicationContext).also { instance = it }
            }
    }
}
