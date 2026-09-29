package dev.sidejit.pairing

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Accepts the connections an iOS device makes to our advertised pairable host port and
 * runs one [PairableHost] conversation per connection.
 *
 * Only one pairing is handled at a time. A phone that connects while another pairing is
 * in progress is closed immediately rather than queued, because two setup codes on one
 * screen would be worse than a retry.
 */
class PairableHostListener(
    private val identity: HostIdentity,
    private val store: PairingStore,
    private val pinless: Boolean = false,
    private val requestedPort: Int = 0,
) {
    /** Called with the code to show, and with null when the attempt is over. */
    var onSetupCode: (String?) -> Unit = {}

    /** Called when a device finishes pairing. */
    var onPaired: (PairingRecord) -> Unit = {}

    /** Called when an attempt fails, with a short reason suitable for a status screen. */
    var onFailure: (String) -> Unit = {}

    private val running = AtomicBoolean(false)
    private val busy = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null

    /** The port actually bound, available once [start] returns. */
    val port: Int get() = serverSocket?.localPort ?: -1

    @Synchronized
    fun start(): Int {
        if (running.get()) return port
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(requestedPort), BACKLOG)
        serverSocket = socket
        running.set(true)
        acceptThread = Thread({ acceptLoop(socket) }, "pairable-host").apply {
            isDaemon = true
            start()
        }
        Log.i(LogTag.PAIRING, "listening for device initiated pairing on port ${socket.localPort}")
        return socket.localPort
    }

    @Synchronized
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread?.join(1000)
        acceptThread = null
        Log.i(LogTag.PAIRING, "stopped listening for pairing")
    }

    private fun acceptLoop(socket: ServerSocket) {
        while (running.get() && !socket.isClosed) {
            val connection = try {
                socket.accept()
            } catch (failure: Exception) {
                if (running.get()) Log.d(LogTag.PAIRING, "accept failed: ${failure.describe()}")
                continue
            }
            if (!busy.compareAndSet(false, true)) {
                Log.w(LogTag.PAIRING, "a second device connected while pairing; closing it")
                runCatching { connection.close() }
                continue
            }
            Thread({
                try {
                    handle(connection)
                } finally {
                    busy.set(false)
                    onSetupCode(null)
                }
            }, "pairable-host-session").apply { isDaemon = true }.start()
        }
    }

    private fun handle(connection: Socket) {
        connection.use { socket ->
            socket.tcpNoDelay = true
            socket.soTimeout = SESSION_TIMEOUT_MILLIS
            Log.i(LogTag.PAIRING, "a device connected from ${socket.inetAddress?.hostAddress}")
            val stream = RpPairingStream(
                BufferedInputStream(socket.getInputStream()),
                BufferedOutputStream(socket.getOutputStream()),
            )
            val host = PairableHost(identity, stream, pinless)
            host.onSetupCode = { code -> onSetupCode(code) }
            try {
                val record = host.accept()
                store.save(record)
                onPaired(record)
            } catch (failure: Exception) {
                Log.w(LogTag.PAIRING, "pairing failed: ${failure.describe()}")
                onFailure(failure.message ?: failure.javaClass.simpleName)
            }
        }
    }

    companion object {
        private const val BACKLOG = 4

        /**
         * A person has to read a code and type it, so the conversation is allowed to be
         * slow, but not to hold the single pairing slot forever.
         */
        const val SESSION_TIMEOUT_MILLIS: Int = 180_000
    }
}