package dev.sidejit.coredevice

import dev.sidejit.core.serialization.JsonValue
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CdTunnelTest {
    @Test
    fun roundTripFrame() {
        val body = """{"type":"clientHandshakeRequest","mtu":1280}""".toByteArray()
        val frame = CdTunnel.encode(body)
        assertTrue(frame.copyOfRange(0, 8).contentEquals("CDTunnel".toByteArray()))
        val packet = CdTunnel.decode(frame)
        assertTrue(packet.body.contentEquals(body))
    }

    @Test
    fun streamRoundTrip() {
        val body = ByteArray(300) { it.toByte() }
        val out = ByteArrayOutputStream()
        CdTunnel.write(out, body)
        val packet = CdTunnel.read(ByteArrayInputStream(out.toByteArray()))
        assertTrue(packet.body.contentEquals(body))
    }

    @Test
    fun parseServerHandshake() {
        val json = JsonValue.parse(
            """
            {
              "clientParameters": {
                "address": "fd58:8c92:8961::2",
                "mtu": 1280,
                "netmask": "ffff:ffff:ffff:ffff::"
              },
              "serverAddress": "fd58:8c92:8961::1",
              "serverRSDPort": 56307,
              "type": "serverHandshakeResponse"
            }
            """.trimIndent(),
        )
        val params = TunnelParameters.fromHandshakeResponse(json)
        assertEquals("fd58:8c92:8961::2", params.clientAddress)
        assertEquals("fd58:8c92:8961::1", params.serverAddress)
        assertEquals(1280, params.mtu)
        assertEquals(56307, params.serverRsdPort)
    }

    @Test
    fun createListenerRequestShape() {
        val req = CreateListener.tcpRequest("dGVzdA==")
        assertEquals(
            "tcp",
            req.path("request", "_0", "createListener", "transportProtocolType")?.asText,
        )
        assertEquals(
            "dGVzdA==",
            req.path("request", "_0", "createListener", "key")?.asText,
        )
    }

    @Test
    fun rsdHandshakeParse() {
        val json = JsonValue.parse(
            """
            {
              "MessageType": "Handshake",
              "MessagingProtocolVersion": 3,
              "UUID": "1d701c76-cf8e-45c7-a6c9-d794ee85411c",
              "Properties": { "ProductType": "iPhone15,3", "OSVersion": "17.0" },
              "Services": {
                "com.apple.internal.dt.coredevice.untrusted.tunnelservice": {
                  "Entitlement": "com.apple.dt.coredevice.tunnelservice.client",
                  "Port": "52291",
                  "Properties": { "UsesRemoteXPC": true }
                }
              }
            }
            """.trimIndent(),
        )
        val hs = Rsd.parseHandshake(json)
        assertEquals(3, hs.protocolVersion)
        assertEquals(1, hs.services.size)
        assertEquals(52291, hs.services[0].port)
        assertTrue(hs.services[0].usesRemoteXpc)
        assertEquals("iPhone15,3", hs.properties["ProductType"])
    }
}
