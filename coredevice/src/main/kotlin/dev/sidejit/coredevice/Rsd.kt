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
            throw RsdException("expected RSD Handshake, got $type")
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
    /** RSD on modern CoreDevice is RemoteXPC over HTTP/2, not raw length-prefixed JSON. */
    fun readHandshake(): Rsd.Handshake {
        val h2 = H2Connection(input, output)
        var lastError: Exception? = null
        repeat(6) {
            val message = h2.readXpcMessage(streamId = 1)
            try {
                return parseXpcHandshake(message)
            } catch (failure: Rsd.RsdException) {
                lastError = failure
            }
        }
        throw Rsd.RsdException(
            "RSD handshake message was not found after six XPC messages: " + (lastError?.message ?: "unknown error"),
        )
    }

    private fun parseXpcHandshake(message: XpcCodec.Message): Rsd.Handshake {
        val root = message.body as? XpcCodec.Value.DictionaryValue
            ?: throw Rsd.RsdException("RSD XPC handshake body is not a dictionary")

        val type = root.entries["MessageType"] as? XpcCodec.Value.StringValue
            ?: throw Rsd.RsdException("RSD handshake is missing MessageType")
        if (type.value != "Handshake") {
            throw Rsd.RsdException("unexpected RSD message type: " + type.value)
        }

        val properties = root.entries["Properties"] as? XpcCodec.Value.DictionaryValue
            ?: throw Rsd.RsdException("RSD handshake is missing Properties")
        val udid = (properties.entries["UniqueDeviceID"] as? XpcCodec.Value.StringValue)?.value
            ?: throw Rsd.RsdException("RSD handshake is missing UniqueDeviceID")

        val services = linkedMapOf<String, Rsd.Service>()
        val serviceDict = root.entries["Services"] as? XpcCodec.Value.DictionaryValue
        if (serviceDict != null) {
            for ((name, rawService) in serviceDict.entries) {
                val service = rawService as? XpcCodec.Value.DictionaryValue ?: continue
                val port: Int = when (val rawPort = service.entries["Port"]) {
                    is XpcCodec.Value.StringValue -> rawPort.value.toIntOrNull() ?: continue
                    is XpcCodec.Value.UInt64Value -> rawPort.value.toIntOrNullOrNull()
                    is XpcCodec.Value.Int64Value -> rawPort.value.toInt().takeIf { rawPort.value in 1..65535 }
                    else -> null
                } ?: continue
                if (port !in 1..65535) continue

                val serviceProperties = service.entries["Properties"] as? XpcCodec.Value.DictionaryValue
                val usesRemoteXpc =
                    (serviceProperties?.entries?.get("UsesRemoteXPC") as? XpcCodec.Value.Bool)?.value == true

                services[name] = Rsd.Service(
                    name = name,
                    port = port,
                    entitlement = (service.entries["Entitlement"] as? XpcCodec.Value.StringValue)?.value,
                    usesRemoteXpc = usesRemoteXpc,
                )
            }
        }

        val protocolVersion = when (val version = root.entries["MessagingProtocolVersion"]) {
            is XpcCodec.Value.UInt64Value -> version.value.toInt()
            is XpcCodec.Value.Int64Value -> version.value.toInt()
            is XpcCodec.Value.StringValue -> version.value.toIntOrNull() ?: 0
            else -> 0
        }

        return Rsd.Handshake(
            uuid = (root.entries["UUID"] as? XpcCodec.Value.StringValue)?.value,
            protocolVersion = protocolVersion,
            services = services.values.toList(),
            properties = properties.entries.mapNotNull { (key, value) ->
                val text = when (value) {
                    is XpcCodec.Value.StringValue -> value.value
                    is XpcCodec.Value.UInt64Value -> value.value.toString()
                    is XpcCodec.Value.Int64Value -> value.value.toString()
                    is XpcCodec.Value.Bool -> value.value.toString()
                    else -> null
                }
                text?.let { key to it }
            }.toMap(),
        ).also {
            require(udid.isNotBlank()) { "RSD UniqueDeviceID is blank" }
        }
    }
}
