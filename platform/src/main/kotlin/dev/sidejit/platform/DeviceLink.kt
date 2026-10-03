package dev.sidejit.platform

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.coredevice.CoreDeviceTunnel
import dev.sidejit.pairing.DeviceConnector
import dev.sidejit.pairing.HostIdentity
import dev.sidejit.pairing.PairingStore
import dev.sidejit.pairing.VerifiedSession
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Keeps an outbound, verified control channel to a paired device alive.
 *
 * The device only dials into us while a person is pairing. Afterwards it just advertises
 * `_remotepairing._tcp` and waits. Everything JIT needs hangs off a connection we open, so this
 * browses for the device, verifies, asks for a tunnel listener, and holds the socket until the
 * device goes away - then starts over.
 */
class DeviceLink(
    private val identity: HostIdentity,
    private val store: PairingStore,
    private val onSearching: () -> Unit = {},
    private val onVerified: (VerifiedSession, String) -> Unit = { _, _ -> },
    private val onListener: (String, Int) -> Unit = { _, _ -> },
    private val onTunnel: (String, Int, String) -> Unit = { _, _, _ -> },
    private val onLost: (String) -> Unit = {},
) {
    private val running = AtomicBoolean(false)
    private val gate = java.lang.Object()
    private var thread: Thread? = null

    @Volatile
    private var connection: DeviceConnector.Connection? = null

    @Volatile
    private var tunnel: CoreDeviceTunnel.OpenedTunnel? = null

    /** Serialises tunnel use: the loop builds it, the HTTP API runs requests over it. */
    private val tunnelLock = Any()

    /** The live channel, or null when nothing is connected. */
    val current: DeviceConnector.Connection? get() = connection

    /** True once a CoreDevice tunnel is up and usable. */
    val hasTunnel: Boolean get() = tunnel != null

    /**
     * Runs [block] against the live tunnel, or returns null when there is none.
     *
     * Calls are serialised because one tunnel carries every userspace TCP connection.
     */
    fun <T> withTunnel(block: (CoreDeviceTunnel.OpenedTunnel) -> T): T? =
        synchronized(tunnelLock) { tunnel?.let(block) }

    @Synchronized
    fun start() {
        if (!running.compareAndSet(false, true)) return
        thread = Thread(::loop, "device-link").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Throws the tunnel away and builds a new one.
     *
     * An idle tunnel can be closed by the device without telling us, so a failed request is
     * reason enough to rebuild rather than to keep retrying over a dead socket.
     */
    fun invalidateTunnel() {
        closeTunnel()
        nudge()
    }

    /** Wakes the loop early, for instance right after a device finishes pair setup. */
    fun nudge() {
        synchronized(gate) { gate.notifyAll() }
    }

    @Synchronized
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        nudge()
        thread?.interrupt()
        closeTunnel()
        runCatching { connection?.close() }
        connection = null
        thread?.join(2_000)
        thread = null
    }

    private fun loop() {
        while (running.get()) {
            val live = connection
            if (live != null && live.isOpen) {
                if (tunnel == null && !bringUpTunnel(live)) {
                    // The session is no longer useful for a tunnel; start again from discovery.
                    drop("the tunnel could not be established on this session")
                    if (!sleep(IDLE_RETRY_MILLIS)) return
                    continue
                }
                if (!sleep(HEALTHY_POLL_MILLIS)) return
                continue
            }
            if (live != null) {
                drop("the device closed the control connection")
            }
            if (store.all().isEmpty()) {
                if (!sleep(IDLE_RETRY_MILLIS)) return
                continue
            }
            onSearching()
            val opened = try {
                DeviceConnector.discoverAndConnect(identity, store)
            } catch (failure: InterruptedException) {
                return
            } catch (failure: Exception) {
                Log.w(LogTag.PAIRING, "reconnect attempt failed: ${failure.describe()}")
                onLost(failure.message ?: failure.javaClass.simpleName)
                null
            }
            if (opened == null) {
                if (!sleep(IDLE_RETRY_MILLIS)) return
                continue
            }
            connection = opened
            onVerified(opened.session, opened.host)
        }
    }

    /**
     * Asks for a listener and connects to it straight away.
     *
     * iOS closes a listener that nothing connects to, so the port has to be used now and the
     * tunnel kept open for as long as JIT might be wanted. Requesting a port and saving it for
     * later gets a refused connection.
     */
    private fun bringUpTunnel(live: DeviceConnector.Connection): Boolean {
        val port = try {
            live.channel.createListener()
        } catch (failure: Exception) {
            Log.w(LogTag.TUNNEL, "createListener failed: ${failure.describe()}")
            onLost("createListener failed: ${failure.message ?: failure.javaClass.simpleName}")
            return false
        }
        onListener(live.host, port)
        return try {
            val opened = CoreDeviceTunnel.openDataPlane(live.host, port, live.session.sharedSecret)
            synchronized(tunnelLock) { tunnel = opened }
            Log.i(
                LogTag.TUNNEL,
                "tunnel up to ${live.host}:$port rsd=${opened.parameters.serverRsdPort}",
            )
            onTunnel(live.host, port, "rsd port ${opened.parameters.serverRsdPort}")
            true
        } catch (failure: Exception) {
            Log.w(LogTag.TUNNEL, "the tunnel data plane failed: ${failure.describe()}")
            onLost("tunnel to port $port failed: ${failure.message ?: failure.javaClass.simpleName}")
            false
        }
    }

    private fun drop(reason: String) {
        closeTunnel()
        val live = connection
        connection = null
        runCatching { live?.close() }
        onLost(reason)
    }

    private fun closeTunnel() {
        synchronized(tunnelLock) {
            runCatching { tunnel?.close() }
            tunnel = null
        }
    }

    /** Waits up to [millis], or until nudged. Returns false when the link was asked to stop. */
    private fun sleep(millis: Long): Boolean {
        synchronized(gate) {
            try {
                gate.wait(millis)
            } catch (_: InterruptedException) {
                return false
            }
        }
        return running.get()
    }

    companion object {
        private const val IDLE_RETRY_MILLIS = 20_000L
        private const val HEALTHY_POLL_MILLIS = 5_000L
    }
}
