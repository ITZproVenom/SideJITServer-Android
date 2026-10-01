package dev.sidejit.coredevice

import dev.sidejit.core.serialization.JsonValue
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Base64

/**
 * CDTunnel framing used after the TLS-PSK (or QUIC) transport is up.
 *
 * Wire form: ASCII `CDTunnel` + big-endian uint16 length + body bytes (JSON).
 * First exchange is clientHandshakeRequest / serverHandshakeResponse which yields
 * the virtual IPv6 addresses, MTU, and trusted RSD port.
 */
object CdTunnel {
    val MAGIC: ByteArray = "CDTunnel".toByteArray(Charsets.US_ASCII)

    data class Packet(val body: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Packet && other.body.contentEquals(body)

        override fun hashCode(): Int = body.contentHashCode()
    }

    fun encode(body: ByteArray): ByteArray {
        require(body.size <= 0xFFFF) { "CDTunnel body too large: ${body.size}" }
        val out = ByteArray(MAGIC.size + 2 + body.size)
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.size)
        out[MAGIC.size] = ((body.size ushr 8) and 0xFF).toByte()
        out[MAGIC.size + 1] = (body.size and 0xFF).toByte()
        System.arraycopy(body, 0, out, MAGIC.size + 2, body.size)
        return out
    }

    fun encodeJson(value: JsonValue): ByteArray =
        encode(value.encode().toByteArray(Charsets.UTF_8))

    fun decode(frame: ByteArray): Packet {
        require(frame.size >= MAGIC.size + 2) { "frame too short" }
        require(frame.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            "not a CDTunnel frame"
        }
        val length = ((frame[MAGIC.size].toInt() and 0xFF) shl 8) or
            (frame[MAGIC.size + 1].toInt() and 0xFF)
        require(frame.size == MAGIC.size + 2 + length) {
            "length $length does not match frame size ${frame.size}"
        }
        return Packet(frame.copyOfRange(MAGIC.size + 2, frame.size))
    }

    fun read(input: InputStream): Packet {
        val magic = readExactly(input, MAGIC.size)
        if (!magic.contentEquals(MAGIC)) {
            throw CdTunnelException("expected CDTunnel magic")
        }
        val header = readExactly(input, 2)
        val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
        return Packet(readExactly(input, length))
    }

    fun write(output: OutputStream, body: ByteArray) {
        output.write(encode(body))
        output.flush()
    }

    fun writeJson(output: OutputStream, value: JsonValue) {
        write(output, value.encode().toByteArray(Charsets.UTF_8))
    }

    private fun readExactly(input: InputStream, count: Int): ByteArray {
        val buf = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(buf, read, count - read)
            if (n < 0) throw EOFException("EOF after $read of $count")
            read += n
        }
        return buf
    }
}

class CdTunnelException(message: String) : Exception(message)

/** Parameters negotiated in the CDTunnel handshake. */
data class TunnelParameters(
    val clientAddress: String,
    val serverAddress: String,
    val netmask: String,
    val mtu: Int,
    val serverRsdPort: Int,
) {
    companion object {
        fun fromHandshakeResponse(json: JsonValue): TunnelParameters {
            val type = json.path("type")?.asText
            if (type != null && type != "serverHandshakeResponse") {
                throw CdTunnelException("expected serverHandshakeResponse, got $type")
            }
            val client = json.path("clientParameters")
                ?: throw CdTunnelException("missing clientParameters")
            return TunnelParameters(
                clientAddress = client.path("address")?.asText
                    ?: throw CdTunnelException("missing client address"),
                serverAddress = json.path("serverAddress")?.asText
                    ?: throw CdTunnelException("missing serverAddress"),
                netmask = client.path("netmask")?.asText ?: "ffff:ffff:ffff:ffff::",
                mtu = client.path("mtu")?.asLong?.toInt() ?: 1280,
                serverRsdPort = json.path("serverRSDPort")?.asLong?.toInt()
                    ?: throw CdTunnelException("missing serverRSDPort"),
            )
        }
    }
}

/**
 * Request the device open a TCP-PSK listener for the CoreDevice tunnel.
 * Sent encrypted on the RPPairing control channel after pair-verify.
 */
object CreateListener {
    fun tcpRequest(pskKeyBase64: String): JsonValue =
        JsonValue.parse(
            """{"request":{"_0":{"createListener":{"key":"$pskKeyBase64","transportProtocolType":"tcp"}}}}""",
        )

    fun extractPort(response: JsonValue): Int {
        val port = response.path("createListener", "port")?.asLong
            ?: response.path("response", "_1", "createListener", "port")?.asLong
            ?: response.path("response", "_0", "createListener", "port")?.asLong
            ?: throw CdTunnelException("createListener response had no port")
        return port.toInt()
    }

    fun keyFromSession(sharedSecret: ByteArray): String =
        Base64.getEncoder().encodeToString(sharedSecret)
}

/** Client handshake request body after TLS is up. */
object ClientHandshake {
    fun request(): JsonValue =
        JsonValue.parse("""{"type":"clientHandshakeRequest","mtu":1280}""")
}
