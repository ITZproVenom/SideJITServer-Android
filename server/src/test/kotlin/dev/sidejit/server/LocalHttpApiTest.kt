package dev.sidejit.server

import dev.sidejit.jit.JitEngine
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Drives the API over a real loopback socket, because the routing and the HTTP framing are both
 * part of what a client sees.
 */
class LocalHttpApiTest {

    private lateinit var api: LocalHttpApi
    private val launched = ArrayList<String>()

    @Volatile
    private var grantPid: Long? = null

    private val devices = ArrayList<DeviceSummary>()

    @Before
    fun start() {
        api = LocalHttpApi(
            port = 0,
            bindAddress = InetAddress.getLoopbackAddress(),
            statusProvider = { """{"ok":true,"jit":"not_ready"}""" },
            launchHandler = { bundleId ->
                synchronized(launched) { launched.add(bundleId) }
                grantPid?.let { JitEngine.Result.Granted(bundleId, it) }
                    ?: JitEngine.Result.Failed("no tunnel in this test")
            },
            deviceProvider = { synchronized(devices) { devices.toList() } },
        )
        api.start()
    }

    @After
    fun stop() {
        api.stop()
    }

    private data class Response(val status: Int, val body: String)

    private fun request(path: String, method: String = "GET"): Response {
        Socket(InetAddress.getLoopbackAddress(), api.boundPort).use { socket ->
            socket.soTimeout = 10_000
            val writer = OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8)
            writer.write("$method $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            writer.flush()
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
            val statusLine = reader.readLine() ?: throw AssertionError("no status line")
            val status = statusLine.split(' ')[1].toInt()
            while (true) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) break
            }
            return Response(status, reader.readText())
        }
    }

    @Test
    fun `the root and status both report the server state`() {
        assertEquals("""{"ok":true,"jit":"not_ready"}""", request("/").body)
        assertEquals("""{"ok":true,"jit":"not_ready"}""", request("/status").body)
    }

    @Test
    fun `the version and refresh routes accept a trailing slash`() {
        // A SideJITServer client asks for these exactly as /ver/ and /re/.
        assertTrue(request("/ver/").body.contains(LocalHttpApi.VERSION))
        assertTrue(request("/version").body.contains(LocalHttpApi.VERSION))
        assertEquals(200, request("/re/").status)
    }

    @Test
    fun `a udid and bundle identifier path enables jit for that bundle`() {
        synchronized(devices) { devices.add(DeviceSummary("00008120-ABC", "Bestin's iPhone")) }
        grantPid = 4321
        val response = request("/00008120-ABC/com.example.app/")
        assertEquals(200, response.status)
        assertTrue(response.body.contains("\"pid\":4321"))
        assertEquals(listOf("com.example.app"), synchronized(launched) { launched.toList() })
    }

    @Test
    fun `a bundle identifier alone is accepted`() {
        grantPid = 99
        assertEquals(200, request("/com.example.app/").status)
        assertEquals(listOf("com.example.app"), synchronized(launched) { launched.toList() })
    }

    @Test
    fun `a percent encoded bundle identifier is decoded`() {
        grantPid = 7
        assertEquals(200, request("/com%2Eexample%2Eapp/").status)
        assertEquals(listOf("com.example.app"), synchronized(launched) { launched.toList() })
    }

    @Test
    fun `a request for an unknown device is refused rather than launched`() {
        synchronized(devices) { devices.add(DeviceSummary("00008120-ABC", "Bestin's iPhone")) }
        val response = request("/somebody-elses-phone/com.example.app/")
        assertEquals(404, response.status)
        assertTrue(synchronized(launched) { launched.isEmpty() })
    }

    @Test
    fun `asking for a device on its own says listing apps is not implemented`() {
        synchronized(devices) { devices.add(DeviceSummary("00008120-ABC", "Bestin's iPhone")) }
        val response = request("/00008120-ABC/")
        assertEquals(501, response.status)
        assertTrue(response.body.contains("not implemented"))
    }

    @Test
    fun `a failed launch reports the reason and does not claim success`() {
        grantPid = null
        val response = request("/com.example.app/")
        assertEquals(503, response.status)
        assertTrue(response.body.contains("no tunnel in this test"))
        assertTrue(response.body.contains("\"ok\":false"))
    }

    @Test
    fun `the query parameter form still works`() {
        grantPid = 11
        assertEquals(200, request("/launch?bundleId=com.example.app").status)
        assertEquals(listOf("com.example.app"), synchronized(launched) { launched.toList() })
    }

    @Test
    fun `an unknown path is a not found`() {
        assertEquals(404, request("/a/b/c/d").status)
        assertEquals(404, request("/nodots").status)
    }
}
