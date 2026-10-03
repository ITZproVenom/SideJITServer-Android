package dev.sidejit.pairing

import dev.sidejit.core.crypto.ChaChaPoly
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.serialization.JsonValue
import java.util.Base64

/**
 * Requests that travel over the RPPairing control channel after pair verify.
 *
 * The channel stays on the same TCP connection, but every payload is now sealed with
 * ChaCha20-Poly1305 under the session keys. The nonce is a counter that advances once per
 * request and reply pair, and the same counter value seals the request and opens its reply.
 */
object RemotePairingControl {

    class ControlException(message: String) : Exception(message)

    /** Tracks the encrypted sequence number for one verified connection. */
    class Channel(
        private val stream: RpPairingStream,
        private val session: VerifiedSession,
    ) {
        private var sequence = 0L

        /** Sends [request], waits for the matching reply, and returns it decoded. */
        @Synchronized
        fun exchange(request: JsonValue): JsonValue {
            val nonce = ChaChaPoly.rppairingNonce(sequence)
            stream.sendEncrypted(
                ChaChaPoly.seal(
                    session.keys.writeKey,
                    nonce,
                    request.encode().toByteArray(Charsets.UTF_8),
                ),
            )
            val reply = when (val message = stream.receive()) {
                is RpMessage.Plain ->
                    throw ControlException("a post verify reply arrived unencrypted: ${message.value.encode().take(200)}")
                is RpMessage.Encrypted -> {
                    val plain = try {
                        ChaChaPoly.open(session.keys.readKey, nonce, message.ciphertext)
                    } catch (failure: ChaChaPoly.AuthenticationFailure) {
                        throw ControlException("a post verify reply did not decrypt: ${failure.message}")
                    }
                    JsonValue.parse(String(plain, Charsets.UTF_8))
                }
            }
            sequence++
            return reply
        }

        /**
         * Asks the device to open a tunnel listener and returns the TCP port it chose.
         *
         * iOS only honours this on a connection the host opened to the device's
         * `_remotepairing._tcp` service. On a connection the device opened to us we are the
         * accessory and the request is refused, which is why pairing can succeed while the
         * tunnel never appears.
         */
        fun createListener(): Int {
            val reply = exchange(JsonValue.parse(createListenerRequest(session)))
            val port = reply.path("createListener", "port")?.asLong
                ?: reply.path("response", "_1", "createListener", "port")?.asLong
                ?: reply.path("response", "_0", "createListener", "port")?.asLong
                ?: throw ControlException("createListener reply had no port: ${reply.encode().take(200)}")
            if (port !in 1..65535) throw ControlException("createListener returned invalid port $port")
            Log.i(LogTag.TUNNEL, "createListener returned port $port")
            return port.toInt()
        }
    }

    /** The createListener request body, keyed with the verified shared secret. */
    fun createListenerRequest(session: VerifiedSession): String {
        val key = Base64.getEncoder().encodeToString(session.sharedSecret)
        return """{"request":{"_0":{"createListener":{"key":"$key","transportProtocolType":"tcp"}}}}"""
    }
}
