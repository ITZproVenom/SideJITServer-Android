package dev.sidejit.coredevice

import dev.sidejit.core.serialization.JsonValue
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal HTTP/2 framing used by RemoteXPC.
 *
 * Apple's RemoteXPC is XPC dictionaries over a non-compliant HTTP/2 stream.
 * This implements frame header encode/decode and a simple request writer so higher
 * layers can speak once a TCP channel to an RSD service port exists.
 */
object Http2 {
    const val FRAME_DATA = 0x0
    const val FRAME_HEADERS = 0x1
    const val FRAME_SETTINGS = 0x4
    const val FRAME_WINDOW_UPDATE = 0x8
    const val FRAME_CONTINUATION = 0x9

    const val FLAG_END_STREAM = 0x1
    const val FLAG_END_HEADERS = 0x4
    const val FLAG_ACK = 0x1

    data class Frame(
        val type: Int,
        val flags: Int,
        val streamId: Int,
        val payload: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Frame && type == other.type && flags == other.flags &&
                streamId == other.streamId && payload.contentEquals(other.payload)

        override fun hashCode(): Int =
            ((type * 31 + flags) * 31 + streamId) * 31 + payload.contentHashCode()
    }

    fun encodeFrame(type: Int, flags: Int, streamId: Int, payload: ByteArray): ByteArray {
        require(payload.size <= 0xFFFFFF) { "frame too large" }
        val out = ByteArray(9 + payload.size)
        out[0] = ((payload.size ushr 16) and 0xFF).toByte()
        out[1] = ((payload.size ushr 8) and 0xFF).toByte()
        out[2] = (payload.size and 0xFF).toByte()
        out[3] = type.toByte()
        out[4] = flags.toByte()
        out[5] = ((streamId ushr 24) and 0x7F).toByte()
        out[6] = ((streamId ushr 16) and 0xFF).toByte()
        out[7] = ((streamId ushr 8) and 0xFF).toByte()
        out[8] = (streamId and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 9, payload.size)
        return out
    }

    fun decodeFrame(bytes: ByteArray): Frame {
        require(bytes.size >= 9) { "HTTP/2 frame header is 9 bytes" }
        val length = ((bytes[0].toInt() and 0xFF) shl 16) or
            ((bytes[1].toInt() and 0xFF) shl 8) or
            (bytes[2].toInt() and 0xFF)
        require(bytes.size >= 9 + length) { "truncated frame" }
        val type = bytes[3].toInt() and 0xFF
        val flags = bytes[4].toInt() and 0xFF
        val streamId = ((bytes[5].toInt() and 0x7F) shl 24) or
            ((bytes[6].toInt() and 0xFF) shl 16) or
            ((bytes[7].toInt() and 0xFF) shl 8) or
            (bytes[8].toInt() and 0xFF)
        return Frame(type, flags, streamId, bytes.copyOfRange(9, 9 + length))
    }

    fun readFrame(input: InputStream): Frame {
        val header = ByteArray(9)
        var read = 0
        while (read < 9) {
            val n = input.read(header, read, 9 - read)
            if (n < 0) throw java.io.EOFException("EOF in HTTP/2 header")
            read += n
        }
        val length = ((header[0].toInt() and 0xFF) shl 16) or
            ((header[1].toInt() and 0xFF) shl 8) or
            (header[2].toInt() and 0xFF)
        val payload = ByteArray(length)
        read = 0
        while (read < length) {
            val n = input.read(payload, read, length - read)
            if (n < 0) throw java.io.EOFException("EOF in HTTP/2 payload")
            read += n
        }
        return decodeFrame(header + payload)
    }

    /** Client connection preface. */
    val CLIENT_PREFACE: ByteArray =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

    fun settingsFrame(ack: Boolean = false): ByteArray =
        encodeFrame(FRAME_SETTINGS, if (ack) FLAG_ACK else 0, 0, ByteArray(0))
}

object RemoteXpc {
    /** Wrap a JSON body as a DATA frame on stream 1 with END_STREAM. */
    fun dataFrame(json: JsonValue, streamId: Int = 1, endStream: Boolean = true): ByteArray {
        val payload = json.encode().toByteArray(Charsets.UTF_8)
        val flags = if (endStream) Http2.FLAG_END_STREAM else 0
        return Http2.encodeFrame(Http2.FRAME_DATA, flags, streamId, payload)
    }

    fun writePreface(output: OutputStream) {
        output.write(Http2.CLIENT_PREFACE)
        output.write(Http2.settingsFrame())
        output.flush()
    }
}
