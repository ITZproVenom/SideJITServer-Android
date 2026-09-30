package dev.sidejit.server

import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.jsonObject
import dev.sidejit.jit.JitOrchestrator
import dev.sidejit.jit.UnavailableConnector
import dev.sidejit.jit.UnavailableProcessResolver
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

class LocalApiTest {
    private val api = LocalApi(
        JitOrchestrator(UnavailableProcessResolver, UnavailableConnector),
        { jsonObject("jit" to JsonValue.of("not implemented")) },
        InetAddress.getLoopbackAddress(), 0,
    )

    @After fun stop() = api.stop()

    private fun get(path: String): Pair<Int, String> {
        val c = URL("http://127.0.0.1:${api.port}$path").openConnection() as HttpURLConnection
        val code = c.responseCode
        val text = (if (code < 400) c.inputStream else c.errorStream).readBytes().decodeToString()
        return code to text
    }

    @Test fun healthAndStatus() {
        api.start()
        assertEquals(200 to "{\"ok\":true}", get("/health"))
        assertEquals(200, get("/status").first)
    }

    @Test fun jitFailsHonestlyWhileTheStackIsIncomplete() {
        api.start()
        val (code, body) = get("/jit/com.example.app")
        assertEquals(503, code)
        assertTrue(body.contains("\"granted\":false"))
        assertTrue(body.contains("\"stage\":\"DVT\""))
    }

    @Test fun unknownRouteIs404() {
        api.start()
        assertEquals(404, get("/nope").first)
    }

    @Test fun onlyLocalAddressesAreServed() {
        assertTrue(LocalApi.isLocal(InetAddress.getByName("192.168.1.20")))
        assertTrue(LocalApi.isLocal(InetAddress.getByName("10.0.0.5")))
        assertTrue(LocalApi.isLocal(InetAddress.getByName("fd00::1")))
        assertFalse(LocalApi.isLocal(InetAddress.getByName("8.8.8.8")))
        assertFalse(LocalApi.isLocal(InetAddress.getByName("2001:4860:4860::8888")))
    }
}
