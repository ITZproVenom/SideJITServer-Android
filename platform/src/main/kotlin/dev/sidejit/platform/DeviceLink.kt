package dev.sidejit.platform

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
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
    private val onLost: (String) -> Unit = {},
) {
    private val running = AtomicBoolean(false)
    private val gate = java.lang.Object()
    private var thread: Thread? = null

    @Volatile
    private var connection: DeviceConnector.Connection? = null

    /** The live channel, or null when nothing is connected. */
    val current: DeviceConnector.Connection? get() = connection

    @Synchronized
    fun start() {
        if (!running.compareAndSet(false, true)) return
        thread = Thread(::loop, "device-link").apply {
            isDaemon = true
            start()
        }
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
        runCatching { connection?.close() }
        connection = null
        thread?.join(2_000)
        thread = null
    }

    private fun loop() {
        while (running.get()) {
            val live = connection
            if (live != null && live.isOpen) {
                if (!sleep(HEALTHY_POLL_MILLIS)) return
                continue
            }
            if (live != null) {
                connection = null
                runCatching { live.close() }
                onLost("the device closed the control connection")
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
            try {
                val port = opened.channel.createListener()
                onListener(opened.host, port)
            } catch (failure: Exception) {
                Log.w(LogTag.TUNNEL, "createListener on the outbound channel failed: ${failure.describe()}")
                onLost("createListener failed: ${failure.message ?: failure.javaClass.simpleName}")
                // Keep the connection: the session is still valid and a later request may work.
            }
            if (!sleep(HEALTHY_POLL_MILLIS)) return
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
