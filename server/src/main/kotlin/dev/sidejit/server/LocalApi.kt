package dev.sidejit.server

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.jsonObject
import dev.sidejit.jit.JitOrchestrator
import dev.sidejit.jit.JitResult
import java.io.BufferedInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The small HTTP API that SideStore-style clients call.
 *
 *     GET  /health           -> {"ok":true}
 *     GET  /status           -> whatever [statusProvider] returns
 *     GET|POST /jit/<bundle> -> attempt to enable JIT for that bundle id
 *
 * Only clients on the local network are served: loopback, private IPv4,
 * link-local and IPv6 unique-local addresses. Anything else gets 403. The
 * route names are this project's own; they have not been checked against a
 * particular SideStore release.
 */
class LocalApi(
    private val orchestrator: JitOrchestrator,
    private val statusProvider: () -> JsonValue,
    private val bindAddress: InetAddress? = null,
    private val requestedPort: Int = 8080,
) {
    private var socket: ServerSocket? = null
    private var pool: ExecutorService? = null
    private val running = AtomicBoolean(false)

    val port: Int get() = socket?.localPort ?: -1

    fun start(): Int {
        check(running.compareAndSet(false, true)) { "already started" }
        val s = ServerSocket()
        s.reuseAddress = true
        s.bind(InetSocketAddress(bindAddress, requestedPort))
        socket = s
        pool = Executors.newCachedThreadPool { r -> Thread(r, "local-api").apply { isDaemon = true } }
        pool!!.execute { acceptLoop(s) }
        Log.i(LogTag.API, "listening on port ${s.localPort}")
        return s.localPort
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { socket?.close() }
        pool?.shutdownNow()
    }

    private fun acceptLoop(s: ServerSocket) {
        while (running.get()) {
            val c = try { s.accept() } catch (_: Exception) { return }
            pool?.execute { handle(c) }
        }
    }

    private fun handle(c: Socket) {
        c.use {
            it.soTimeout = 15_000
            try {
                if (!isLocal(it.inetAddress)) {
                    respond(it, 403, jsonObject("error" to JsonValue.of("only local network clients are served")))
                    return
                }
                val request = readRequestLine(BufferedInputStream(it.getInputStream())) ?: run {
                    respond(it, 400, jsonObject("error" to JsonValue.of("malformed request")))
                    return
                }
                route(it, request.first, request.second)
            } catch (e: Exception) {
                Log.w(LogTag.API, "request failed: ${e.javaClass.simpleName}")
                runCatching { respond(it, 500, jsonObject("error" to JsonValue.of("internal error"))) }
            }
        }
    }

    private fun route(c: Socket, method: String, target: String) {
        val path = target.substringBefore('?')
        when {
            path == "/health" && method == "GET" -> respond(c, 200, jsonObject("ok" to JsonValue.of(true)))
            path == "/status" && method == "GET" -> respond(c, 200, statusProvider())
            path.startsWith("/jit/") && (method == "GET" || method == "POST") -> {
                val bundle = URLDecoder.decode(path.removePrefix("/jit/"), "UTF-8")
                when (val result = orchestrator.enable(bundle)) {
                    is JitResult.Granted -> respond(
                        c, 200,
                        jsonObject(
                            "granted" to JsonValue.of(true),
                            "bundleId" to JsonValue.of(result.bundleId),
                            "pid" to JsonValue.of(result.pid),
                        ),
                    )
                    is JitResult.Failed -> respond(
                        c, 503,
                        jsonObject(
                            "granted" to JsonValue.of(false),
                            "bundleId" to JsonValue.of(result.bundleId),
                            "stage" to JsonValue.of(result.stage),
                            "reason" to JsonValue.of(result.reason),
                        ),
                    )
                }
            }
            else -> respond(c, 404, jsonObject("error" to JsonValue.of("no such route")))
        }
    }

    /** Reads up to the blank line ending the headers; returns method and target. */
    private fun readRequestLine(input: BufferedInputStream): Pair<String, String>? {
        val head = StringBuilder()
        while (head.length < 8192) {
            val b = input.read()
            if (b < 0) break
            head.append(b.toChar())
            if (head.endsWith("\r\n\r\n") || head.endsWith("\n\n")) break
        }
        val first = head.lineSequence().firstOrNull() ?: return null
        val parts = first.trim().split(' ')
        if (parts.size != 3 || !parts[2].startsWith("HTTP/")) return null
        return parts[0] to parts[1]
    }

    private fun respond(c: Socket, code: Int, body: JsonValue) {
        val payload = body.encode().toByteArray(Charsets.UTF_8)
        val reason = when (code) {
            200 -> "OK"; 400 -> "Bad Request"; 403 -> "Forbidden"; 404 -> "Not Found"
            503 -> "Service Unavailable"; else -> "Internal Server Error"
        }
        val head = "HTTP/1.1 $code $reason\r\nContent-Type: application/json\r\n" +
            "Content-Length: ${payload.size}\r\nConnection: close\r\n\r\n"
        c.getOutputStream().apply { write(head.toByteArray(Charsets.US_ASCII)); write(payload); flush() }
    }

    companion object {
        fun isLocal(address: InetAddress): Boolean {
            if (address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress) return true
            val raw = address.address
            // IPv6 unique local fc00::/7
            return raw.size == 16 && (raw[0].toInt() and 0xFE) == 0xFC
        }
    }
}
