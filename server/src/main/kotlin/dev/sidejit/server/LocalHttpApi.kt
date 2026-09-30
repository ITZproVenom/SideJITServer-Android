package dev.sidejit.server

import dev.sidejit.jit.JitEngine
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Minimal HTTP server SideStore / LiveContainer-style clients can hit.
 *
 * GET /  → status JSON
 * GET /version → version string
 * POST /launch?bundleId=… → attempts JIT (fails until live device path works)
 */
class LocalHttpApi(
    private val port: Int = 8080,
    private val bindAddress: InetAddress = InetAddress.getByName("0.0.0.0"),
) {
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private var thread: Thread? = null

    val boundPort: Int get() = server?.localPort ?: -1

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val socket = ServerSocket(port, 50, bindAddress)
        server = socket
        thread = Thread({
            while (running.get() && !socket.isClosed) {
                try {
                    val client = socket.accept()
                    Thread({ handle(client) }, "http-api").apply { isDaemon = true }.start()
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }, "http-api-accept").apply { isDaemon = true }.also { it.start() }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { server?.close() }
        server = null
        thread = null
    }

    private fun handle(socket: Socket) {
        socket.use { s ->
            val reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8))
            val requestLine = reader.readLine() ?: return
            while (true) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) break
            }
            val parts = requestLine.split(' ')
            val method = parts.getOrNull(0) ?: "GET"
            val path = parts.getOrNull(1) ?: "/"
            val (status, body, contentType) = route(method, path)
            val writer = OutputStreamWriter(s.getOutputStream(), Charsets.UTF_8)
            writer.write("HTTP/1.1 $status\r\n")
            writer.write("Content-Type: $contentType\r\n")
            writer.write("Content-Length: ${body.toByteArray(Charsets.UTF_8).size}\r\n")
            writer.write("Connection: close\r\n\r\n")
            writer.write(body)
            writer.flush()
        }
    }

    private fun route(method: String, path: String): Triple<String, String, String> {
        val pathOnly = path.substringBefore('?')
        val query = path.substringAfter('?', "")
        return when {
            method == "GET" && (pathOnly == "/" || pathOnly == "/status") ->
                Triple(
                    "200 OK",
                    """{"ok":true,"jit":"not_ready","stack":${jsonEscape(JitEngine.describeStack())}}""",
                    "application/json",
                )
            method == "GET" && pathOnly == "/version" ->
                Triple("200 OK", "0.1.0-dev", "text/plain; charset=utf-8")
            method == "POST" && pathOnly == "/launch" -> {
                val bundleId = query.substringAfter("bundleId=", "")
                    .substringBefore('&')
                    .ifEmpty { "unknown" }
                val result = JitEngine.enable(bundleId)
                when (result) {
                    is JitEngine.Result.Granted ->
                        Triple("200 OK", """{"ok":true,"pid":${result.pid}}""", "application/json")
                    is JitEngine.Result.Failed ->
                        Triple(
                            "503 Service Unavailable",
                            """{"ok":false,"error":${jsonEscape(result.reason)}}""",
                            "application/json",
                        )
                }
            }
            else -> Triple(
                "404 Not Found",
                """{"ok":false,"error":"not found"}""",
                "application/json",
            )
        }
    }

    private fun jsonEscape(text: String): String =
        buildString {
            append('"')
            for (ch in text) {
                when (ch) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
            append('"')
        }
}
