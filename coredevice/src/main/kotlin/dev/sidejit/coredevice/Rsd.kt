package dev.sidejit.coredevice

import dev.sidejit.core.serialization.JsonValue

/**
 * Remote Service Discovery handshake over the trusted tunnel.
 *
 * The first message on the RSD port is a Handshake with MessagingProtocolVersion and
 * a Services map (name → port/entitlement). Full RemoteXPC/HTTP/2 is still not here.
 */
object Rsd {
    class NotImplemented(message: String = "RSD transport is not implemented yet") : Exception(message)

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
    )

    fun parseHandshake(json: JsonValue): Handshake {
        val type = json.path("MessageType")?.asText
        if (type != null && type != "Handshake") {
            throw CdTunnelException("expected RSD Handshake, got $type")
        }
        val version = json.path("MessagingProtocolVersion")?.asLong?.toInt() ?: 0
        val servicesNode = json.path("Services")
        val services = mutableListOf<Service>()
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

    fun discover(): Nothing = throw NotImplemented(
        "RSD parseHandshake exists; live connect over tunnel IPv6 does not",
    )
}
