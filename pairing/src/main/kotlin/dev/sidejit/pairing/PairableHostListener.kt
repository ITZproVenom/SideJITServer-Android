package dev.sidejit.pairing

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.core.serialization.JsonValue
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Accepts the connections an iOS device makes to our advertised pairable host port and
 * runs one [PairableHost] conversation per connection.
 */
class PairableHostListener(
    private val identity: HostIdentity,
    private val store: PairingStore,
    private val pinless: Boolean = false,
    private val requestedPort: Int = 0,
) {
    var onSetupCode: (String?) -> Unit = {}
    var onPaired: (PairingRecord, String) -> Unit = { _, _ -> }
    var onVerified: (VerifiedSession, String) -> Unit = { _, _ -> }
    /** peerHost, listenerPort from createListener if obtained on this connection */
    var onTunnelListener: (String, Int) -> Unit = { _, _ -> }
    var onTunnelFailure: (String) -> Unit = {}
    var onFailure: (String) -> Unit = {}

    private val running = AtomicBoolean(false)
    private val busy = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null

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
            val peerHost = socket.inetAddress?.hostAddress ?: "unknown"
            Log.i(LogTag.PAIRING, "a device connected from $peerHost")
            val stream = RpPairingStream(
                BufferedInputStream(socket.getInputStream()),
                BufferedOutputStream(socket.getOutputStream()),
            )
            val host = PairableHost(
                identity = identity,
                stream = stream,
                store = store,
                pinless = pinless,
            )
            host.onSetupCode = { code -> onSetupCode(code) }
            try {
                when (val result = host.accept()) {
                    is AcceptResult.Setup -> {
                        onPaired(result.record, peerHost)
                        Log.i(LogTag.PAIRING, "pair-setup finished for ${result.record.peer.name} from $peerHost")
                    }
                    is AcceptResult.Verified -> {
                        onVerified(result.session, peerHost)
                        onPaired(result.session.record, peerHost)
                        Log.i(LogTag.PAIRING, "pair-verify finished for ${result.session.record.peer.name} from $peerHost")
                        tryCreateListener(stream, result.session, peerHost)
                    }
                }
            } catch (failure: Exception) {
                Log.e(LogTag.PAIRING, "pairing attempt failed: ${failure.describe()}", failure)
                onFailure(failure.message ?: failure.javaClass.simpleName)
            }
        }
    }

    /**
     * After pair-verify the control channel can carry createListener.
     * If the device answers with a port, we can open the CoreDevice data plane.
     */
    private fun tryCreateListener(stream: RpPairingStream, session: VerifiedSession, peerHost: String) {
        try {
            val keyB64 = Base64.getEncoder().encodeToString(session.sharedSecret)
            val request = JsonValue.parse(
                """{"request":{"_0":{"createListener":{"key":"$keyB64","peerConnectionsInfo":[{"owningPID":1,"owningProcessName":"SideJITServer"}],"transportProtocolType":"tcp"}}}}""",
            )
            val sealed = try {
                val writeKey = session.keys.writeKey
                dev.sidejit.core.crypto.ChaChaPoly.seal(
                    writeKey,
                    dev.sidejit.core.crypto.ChaChaPoly.nonce(0L),
                    request.encode().toByteArray(Charsets.UTF_8),
                )
            } catch (_: Exception) {
                null
            }
            if (sealed != null) {
                stream.sendEncrypted(sealed)
            } else {
                stream.sendPlain(request)
            }
            val reply = stream.receive()
            val json = when (reply) {
                is RpMessage.Plain -> reply.value
                is RpMessage.Encrypted -> {
                    val plain = dev.sidejit.core.crypto.ChaChaPoly.open(
                        session.keys.readKey,
                        dev.sidejit.core.crypto.ChaChaPoly.nonce(0L),
                        reply.ciphertext,
                    )
                    JsonValue.parse(String(plain, Charsets.UTF_8))
                }
            }
            val port = json.path("createListener", "port")?.asLong
                ?: json.path("response", "_0", "createListener", "port")?.asLong
            if (port != null && port in 1..65535) {
                Log.i(LogTag.PAIRING, "createListener returned port $port for $peerHost")
                onTunnelListener(peerHost, port.toInt())
            } else {
                val reason = if (port == null) {
                    "createListener reply had no port: ${json.encode().take(200)}"
                } else {
                    "createListener returned invalid port $port"
                }
                Log.w(LogTag.PAIRING, reason)
                onTunnelFailure(reason)
            }
        } catch (failure: Exception) {
            val reason = "createListener after verify failed: ${failure.message ?: failure.javaClass.simpleName}"
            Log.w(LogTag.PAIRING, "$reason (${failure.describe()})")
            onTunnelFailure(reason)
        }
    }

    companion object {
        private const val BACKLOG = 4
        const val SESSION_TIMEOUT_MILLIS: Int = 180_000
    }
}
