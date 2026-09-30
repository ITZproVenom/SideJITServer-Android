package dev.sidejit.coredevice

import dev.sidejit.pairing.SessionKeys
import dev.sidejit.pairing.VerifiedSession
import java.util.Base64

/**
 * Orchestration entry for the CoreDevice tunnel.
 *
 * Implemented so far (unit-tested codecs only):
 * - CDTunnel framing
 * - createListener request shape for TCP-PSK
 * - Handshake parameter parsing
 *
 * Not implemented: TLS 1.2 PSK_WITH_AES_256_GCM_SHA384 transport, userspace IPv6
 * packet path, live dial to a device. [open] still fails honestly until those exist.
 */
object CoreDeviceTunnel {
    class NotImplemented(
        message: String = "CoreDevice TLS-PSK transport is not implemented yet",
    ) : Exception(message)

    /** Build the createListener JSON for a verified pairing session. */
    fun createListenerRequest(session: VerifiedSession): String {
        val key = CreateListener.keyFromSession(session.sharedSecret)
        return CreateListener.tcpRequest(key).encode()
    }

    fun createListenerRequest(keys: SessionKeys): String {
        // Prefer the raw shared secret when available; SessionKeys alone are control-channel keys.
        val material = keys.writeKey
        val key = Base64.getEncoder().encodeToString(material)
        return CreateListener.tcpRequest(key).encode()
    }

    fun open(session: VerifiedSession): Nothing {
        throw NotImplemented(
            "tunnel for ${session.record.peer.identifier}: createListener + CDTunnel codecs exist; " +
                "TLS-PSK transport and userspace TCP/IPv6 do not",
        )
    }

    fun open(keys: SessionKeys): Nothing {
        throw NotImplemented(
            "tunnel from SessionKeys: codecs ready, TLS-PSK transport not built",
        )
    }
}
