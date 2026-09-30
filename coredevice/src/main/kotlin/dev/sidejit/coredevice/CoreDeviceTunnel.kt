package dev.sidejit.coredevice

import dev.sidejit.pairing.SessionKeys
import dev.sidejit.pairing.VerifiedSession

/**
 * Placeholder for the TLS-PSK CoreDevice tunnel.
 *
 * After pair-verify the shared secret / [SessionKeys] become the PSK for a TLS 1.2
 * tunnel that carries userspace TCP to RSD. This module does not yet open that
 * tunnel; callers must treat [open] as unimplemented.
 */
object CoreDeviceTunnel {
    class NotImplemented(
        message: String = "CoreDevice TLS-PSK tunnel is not implemented yet",
    ) : Exception(message)

    fun open(session: VerifiedSession): Nothing {
        throw NotImplemented(
            "tunnel for ${session.record.peer.identifier} needs TLS-PSK + userspace TCP " +
                "(keys derived, transport not built)",
        )
    }

    fun open(keys: SessionKeys): Nothing {
        throw NotImplemented("tunnel open from SessionKeys is not implemented yet")
    }
}
