package dev.sidejit.pairing

import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.jsonObject
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.util.Base64

/**
 * One control channel message. The device sends plain envelopes until a session key
 * exists, then switches to encrypted ones.
 */
sealed interface RpMessage {
    data class Plain(val value: JsonValue) : RpMessage
    data class Encrypted(val ciphertext: ByteArray) : RpMessage {
        override fun equals(other: Any?): Boolean =
            other is Encrypted && other.ciphertext.contentEquals(ciphertext)

        override fun hashCode(): Int = ciphertext.contentHashCode()
    }
}

class RpProtocolException(message: String) : Exception(message)

/**
 * The `RPPairing` framing: the literal magic, a big endian sixteen bit length, then a
 * JSON envelope. We are the responder, so every envelope we send is `originatedBy`
 * `device`: in this protocol the side a device pairs *into* plays the accessory.
 */
class RpPairingStream(
    private val input: InputStream,
    private val output: OutputStream,
    private val originatedBy: String = RESPONDER_ROLE,
) {
    private var sequenceNumber = 0L

    fun sendPlain(value: JsonValue) {
        writeFrame(
            jsonObject(
                "message" to jsonObject("plain" to jsonObject("_0" to value)),
                "originatedBy" to JsonValue.of(originatedBy),
                "sequenceNumber" to JsonValue.of(sequenceNumber),
            ),
        )
        sequenceNumber++
    }

    fun sendEncrypted(ciphertext: ByteArray) {
        writeFrame(
            jsonObject(
                "message" to jsonObject(
                    "streamEncrypted" to jsonObject(
                        "_0" to JsonValue.of(Base64.getEncoder().encodeToString(ciphertext)),
                    ),
                ),
                "originatedBy" to JsonValue.of(originatedBy),
                "sequenceNumber" to JsonValue.of(sequenceNumber),
            ),
        )
        sequenceNumber++
    }

    fun receive(): RpMessage {
        val magic = readExactly(MAGIC.size)
        if (!magic.contentEquals(MAGIC)) {
            throw RpProtocolException("the frame did not start with the RPPairing magic")
        }
        val header = readExactly(2)
        val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
        val payload = readExactly(length)
        val envelope = try {
            JsonValue.parse(String(payload, Charsets.UTF_8))
        } catch (failure: JsonValue.Companion.ParseException) {
            throw RpProtocolException("the frame did not contain valid JSON: ${failure.message}")
        }
        envelope.path("message", "plain", "_0")?.let { return RpMessage.Plain(it) }
        envelope.path("message", "streamEncrypted", "_0")?.asText?.let { encoded ->
            val ciphertext = try {
                Base64.getDecoder().decode(encoded)
            } catch (failure: IllegalArgumentException) {
                throw RpProtocolException("the encrypted payload was not base64")
            }
            return RpMessage.Encrypted(ciphertext)
        }
        throw RpProtocolException("the envelope carried neither a plain nor an encrypted message")
    }

    fun receivePlain(): JsonValue = when (val message = receive()) {
        is RpMessage.Plain -> message.value
        is RpMessage.Encrypted -> throw RpProtocolException("expected a plain message, got an encrypted one")
    }

    private fun writeFrame(envelope: JsonValue) {
        val payload = envelope.encode().toByteArray(Charsets.UTF_8)
        if (payload.size > MAX_PAYLOAD) {
            throw RpProtocolException("the envelope is larger than the framing allows")
        }
        val frame = ByteArray(MAGIC.size + 2 + payload.size)
        System.arraycopy(MAGIC, 0, frame, 0, MAGIC.size)
        frame[MAGIC.size] = ((payload.size ushr 8) and 0xFF).toByte()
        frame[MAGIC.size + 1] = (payload.size and 0xFF).toByte()
        System.arraycopy(payload, 0, frame, MAGIC.size + 2, payload.size)
        output.write(frame)
        output.flush()
    }

    private fun readExactly(count: Int): ByteArray {
        val buffer = ByteArray(count)
        var read = 0
        while (read < count) {
            val step = input.read(buffer, read, count - read)
            if (step < 0) throw EOFException("the peer closed the connection after $read of $count bytes")
            read += step
        }
        return buffer
    }

    companion object {
        val MAGIC: ByteArray = "RPPairing".toByteArray(Charsets.US_ASCII)
        const val MAX_PAYLOAD: Int = 0xFFFF

        /** What the accessory side puts in `originatedBy`. */
        const val RESPONDER_ROLE: String = "device"

        /** What an initiating host puts in `originatedBy`. */
        const val INITIATOR_ROLE: String = "host"
    }
}