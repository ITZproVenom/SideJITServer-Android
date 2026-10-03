package dev.sidejit.server

import dev.sidejit.jit.JitEngine
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/** What a client needs to know about a paired device. */
data class DeviceSummary(val udid: String, val name: String)

/**
 * The HTTP API SideStore and LiveContainer talk to.
 *
 * The route shape is SideJITServer's, because that is what the clients already speak: they ask
 * for `/<udid>/<bundle id>/` to enable JIT rather than passing query parameters. Trailing
 * slashes are optional everywhere.
 */
class LocalHttpApi(
    private val port: Int = 8080,
    private val bindAddress: InetAddress = InetAddress.getByName("0.0.0.0"),
    private val statusProvider: () -> String = {
        """{"ok":true,"jit":"not_ready","version":"0.1.0","stack":${jsonEscapeStatic(JitEngine.describeStack())}}"""
    },
    private val launchHandler: (String) -> JitEngine.Result = { JitEngine.enable(it) },
    private val deviceProvider: () -> List<DeviceSummary> = { emptyList() },
    private val diagnosticsProvider: () -> List<String> = { emptyList() },
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
        val segments = pathNorm.split('/').filter { it.isNotEmpty() }.map(::decode)
        return when {
            method == "OPTIONS" -> Triple("204 No Content", "", "text/plain")
            method != "GET" && method != "POST" ->
                Triple("405 Method Not Allowed", error("only GET and POST are served"), JSON)
            pathNorm == "/" || pathNorm == "/status" ->
                Triple("200 OK", statusProvider(), JSON)
            pathNorm == "/ver" || pathNorm == "/version" ->
                Triple("200 OK", """{"ok":true,"version":${jsonEscape(VERSION)}}""", JSON)
            pathNorm == "/re" ->
                // Nothing is cached, so there is nothing to invalidate. The device link keeps
                // itself current; saying so is more honest than claiming a refresh happened.
                Triple(
                    "200 OK",
                    """{"ok":true,"refreshed":false,"note":"the server rediscovers the device continuously"}""",
                    JSON,
                )
            pathNorm == "/diag" || pathNorm == "/diagnostics" -> diagnostics()
            pathNorm == "/launch" || pathNorm == "/launch_app" -> launch(bundleFromQuery(query))
            segments.size == 1 -> single(segments[0])
            segments.size == 2 -> pair(segments[0], segments[1])
            else -> Triple("404 Not Found", error("unknown path", pathNorm), JSON)
        }
    }

    /** What happened on the tunnel, as plain text so it can be read in a browser. */
    private fun diagnostics(): Triple<String, String, String> {
        val lines = diagnosticsProvider()
        val body = if (lines.isEmpty()) {
            "nothing recorded yet. Open a tunnel and try a launch, then reload this page.\n"
        } else {
            lines.joinToString("\n", postfix = "\n")
        }
        return Triple("200 OK", body, "text/plain; charset=utf-8")
    }

    /** `/<bundle id>/` enables JIT; `/<udid>/` would list apps, which is not implemented. */
    private fun single(segment: String): Triple<String, String, String> {
        val devices = deviceProvider()
        if (devices.any { it.udid.equals(segment, ignoreCase = true) }) {
            return Triple(
                "501 Not Implemented",
                error("listing the apps on a device is not implemented; ask for /$segment/<bundle id>/ instead"),
                JSON,
            )
        }
        if (!segment.contains('.')) {
            return Triple(
                "404 Not Found",
                error("no paired device has the identifier $segment, and it is not a bundle identifier"),
                JSON,
            )
        }
        return launch(segment)
    }

    /** `/<udid>/<bundle id>/` is the route SideStore uses to enable JIT. */
    private fun pair(first: String, second: String): Triple<String, String, String> {
        val devices = deviceProvider()
        if (devices.isNotEmpty() && devices.none { it.udid.equals(first, ignoreCase = true) }) {
            return Triple(
                "404 Not Found",
                error(
                    "no paired device has the identifier $first (paired: " +
                        devices.joinToString { it.udid } + ")",
                ),
                JSON,
            )
        }
        return launch(second)
    }

    private fun bundleFromQuery(query: String): String =
        sequenceOf("bundleId", "bundle_id", "bundle")
            .mapNotNull { key ->
                query.split('&')
                    .map { it.substringBefore('=') to it.substringAfter('=', "") }
                    .firstOrNull { it.first.equals(key, ignoreCase = true) }
                    ?.second
                    ?.takeIf { it.isNotBlank() }
                    ?.let(::decode)
            }
            .firstOrNull()
            ?: "unknown"

    private fun launch(bundleId: String): Triple<String, String, String> {
        val result = launchHandler(bundleId)
        return when (result) {
            is JitEngine.Result.Granted ->
                Triple(
                    "200 OK",
                    """{"ok":true,"pid":${result.pid},"bundleId":${jsonEscape(bundleId)}}""",
                    JSON,
                )
            is JitEngine.Result.Failed ->
                Triple(
                    "503 Service Unavailable",
                    """{"ok":false,"error":${jsonEscape(result.reason)},"bundleId":${jsonEscape(bundleId)}}""",
                    JSON,
                )
        }
    }

    private fun error(message: String, path: String? = null): String =
        if (path == null) {
            """{"ok":false,"error":${jsonEscape(message)}}"""
        } else {
            """{"ok":false,"error":${jsonEscape(message)},"path":${jsonEscape(path)}}"""
        }

    /** Percent decoding, because a bundle identifier can arrive encoded. */
    private fun decode(segment: String): String =
        try {
            java.net.URLDecoder.decode(segment, "UTF-8")
        } catch (_: Exception) {
            segment
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
        const val VERSION: String = "0.1.0"
        private const val JSON = "application/json"

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
