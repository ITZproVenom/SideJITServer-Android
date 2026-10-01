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
 */
class LocalHttpApi(
    private val port: Int = 8080,
    private val bindAddress: InetAddress = InetAddress.getByName("0.0.0.0"),
    private val statusProvider: () -> String = {
        """{"ok":true,"jit":"not_ready","version":"0.1.0","stack":${jsonEscapeStatic(JitEngine.describeStack())}}"""
    },
    private val launchHandler: (String) -> JitEngine.Result = { JitEngine.enable(it) },
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
            writer.write("Access-Control-Allow-Origin: *\r\n")
            writer.write("Connection: close\r\n\r\n")
            writer.write(body)
            writer.flush()
        }
    }

    private fun route(method: String, path: String): Triple<String, String, String> {
        val pathOnly = path.substringBefore('?').trimEnd('/')
        val pathNorm = if (pathOnly.isEmpty()) "/" else pathOnly
        val query = path.substringAfter('?', "")
        return when {
            method == "OPTIONS" -> Triple("204 No Content", "", "text/plain")
            method == "GET" && (pathNorm == "/" || pathNorm == "/status") ->
                Triple("200 OK", statusProvider(), "application/json")
            method == "GET" && pathNorm == "/version" ->
                Triple("200 OK", "0.1.0", "text/plain; charset=utf-8")
            method == "GET" && (pathNorm == "/re" || pathNorm.startsWith("/re/")) ->
                Triple("200 OK", """{"ok":true,"refreshed":true}""", "application/json")
            method == "POST" && pathNorm == "/launch" -> launch(query)
            method == "GET" && (pathNorm == "/launch" || pathNorm == "/launch_app") -> launch(query)
            else -> Triple(
                "404 Not Found",
                """{"ok":false,"error":"not found","path":${jsonEscape(pathNorm)}}""",
                "application/json",
            )
        }
    }

    private fun launch(query: String): Triple<String, String, String> {
        val bundleId = sequenceOf("bundleId", "bundle_id", "bundle")
            .map { key ->
                query.split('&')
                    .map { it.substringBefore('=') to it.substringAfter('=', "") }
                    .firstOrNull { it.first.equals(key, ignoreCase = true) }
                    ?.second
                    ?.takeIf { it.isNotBlank() }
            }
            .firstOrNull { it != null }
            ?: "unknown"
        val result = launchHandler(bundleId)
        return when (result) {
            is JitEngine.Result.Granted ->
                Triple("200 OK", """{"ok":true,"pid":${result.pid},"bundleId":${jsonEscape(bundleId)}}""", "application/json")
            is JitEngine.Result.Failed ->
                Triple(
                    "503 Service Unavailable",
                    """{"ok":false,"error":${jsonEscape(result.reason)},"bundleId":${jsonEscape(bundleId)}}""",
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
                    else -> if (ch.code < 0x20) append("\\u%04x".format(ch.code)) else append(ch)
                }
            }
            append('"')
        }

    companion object {
        fun jsonEscapeStatic(text: String): String =
            buildString {
                append('"')
                for (ch in text) {
                    when (ch) {
                        '"' -> append("\\\"")
                        '\\' -> append("\\\\")
                        '\n' -> append("\\n")
                        '\r' -> append("\\r")
                        '\t' -> append("\\t")
                        else -> if (ch.code < 0x20) append("\\u%04x".format(ch.code)) else append(ch)
                    }
                }
                append('"')
            }
    }
}
