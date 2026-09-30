package dev.sidejit.coredevice

import dev.sidejit.core.serialization.JsonValue
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Remote Service Discovery over a byte stream (after the tunnel is up).
 *
 * The trusted RSD handshake is a JSON object with MessageType=Handshake.
 * On some transports it is length-prefixed; on others it is a single read.
 * [RsdClient] tries length-prefixed first, then raw JSON.
 */
object Rsd {
    class RsdException(message: String, cause: Throwable? = null) : Exception(message, cause)

    data class Service(
        val name: String,
        val port: Int,
        val entitlement: String?,
        val usesRemoteXpc: Boolean,
    )

    data class Handshake(
        val uuid: String?,
        val protocolVersion: Int,
        val services: List<Service>,
        val properties: Map<String, String>,
    ) {
        fun service(name: String): Service? = services.firstOrNull { it.name == name }

        fun requireService(name: String): Service =
            service(name) ?: throw RsdException("service not advertised: $name")
    }

    fun parseHandshake(json: JsonValue): Handshake {
        val type = json.path("MessageType")?.asText
        if (type != null && type != "Handshake") {
            throw CdTunnelException("expected RSD Handshake, got $type")
        }
        val version = json.path("MessagingProtocolVersion")?.asLong?.toInt() ?: 0
        val services = mutableListOf<Service>()
        val servicesNode = json.path("Services")
        if (servicesNode is JsonValue.Obj) {
            for ((name, value) in servicesNode.entries) {
                val port = value.path("Port")?.asText?.toIntOrNull()
                    ?: value.path("Port")?.asLong?.toInt()
                    ?: continue
                services += Service(
                    name = name,
                    port = port,
                    entitlement = value.path("Entitlement")?.asText,
                    usesRemoteXpc = value.path("Properties", "UsesRemoteXPC")?.asBool == true,
                )
            }
        }
        val props = mutableMapOf<String, String>()
        val propsNode = json.path("Properties")
        if (propsNode is JsonValue.Obj) {
            for ((k, v) in propsNode.entries) {
                v.asText?.let { props[k] = it }
                    ?: v.asLong?.let { props[k] = it.toString() }
            }
        }
        return Handshake(
            uuid = json.path("UUID")?.asText,
            protocolVersion = version,
            services = services,
            properties = props,
        )
    }

    fun discover(): Nothing =
        throw RsdException("use RsdClient over a live tunnel stream")
}

class RsdClient(
    private val input: InputStream,
    private val output: OutputStream,
) {
    fun readHandshake(): Rsd.Handshake {
        // Prefer 4-byte BE length prefix then JSON body.
        val header = ByteArray(4)
        var n = 0
        while (n < 4) {
            val r = input.read(header, n, 4 - n)
            if (r < 0) throw Rsd.RsdException("EOF reading RSD header")
            n += r
        }
        val size = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).int
        val body = if (size in 2..1_000_000 && header[0] != '{'.code.toByte()) {
            val buf = ByteArray(size)
            var read = 0
            while (read < size) {
                val r = input.read(buf, read, size - read)
                if (r < 0) throw Rsd.RsdException("EOF reading RSD body")
                read += r
            }
            buf
        } else {
            // Not a length prefix — treat accumulated + rest as JSON starting with {
            val rest = input.readBytes()
            header + rest
        }
        val text = String(body, Charsets.UTF_8).trim()
        val start = text.indexOf('{')
        if (start < 0) throw Rsd.RsdException("RSD body is not JSON")
        return Rsd.parseHandshake(JsonValue.parse(text.substring(start)))
    }
}
