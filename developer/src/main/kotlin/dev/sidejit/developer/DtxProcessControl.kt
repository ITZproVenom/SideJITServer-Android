package dev.sidejit.developer

import dev.sidejit.core.serialization.NsKeyedArchive
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Minimal DTX client for Instruments ProcessControl. */
class DtxProcessControl(
    private val input: InputStream,
    private val output: OutputStream,
) : AutoCloseable {
    private var identifier = 5
    private var channelCode = 1

    fun launchSuspended(bundleId: String): Long {
        notifyCapabilities()
        val serviceChannel = requestChannel(ProcessControl.SERVICE)
        val selector = NsKeyedArchive.encode(NsKeyedArchive.text(
            "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"
        ))
        val options = NsKeyedArchive.dict(
            "StartSuspendedKey" to NsKeyedArchive.bool(true),
            "KillExisting" to NsKeyedArchive.bool(true),
        )
        val reply = methodCall(
            serviceChannel,
            selector,
            listOf(
                PrimitiveArg.Bytes(NsKeyedArchive.encode(NsKeyedArchive.text("/private/"))),
                PrimitiveArg.Bytes(NsKeyedArchive.encode(NsKeyedArchive.text(bundleId))),
                PrimitiveArg.Bytes(NsKeyedArchive.encode(NsKeyedArchive.dict(
                    "NSUnbufferedIO" to NsKeyedArchive.text("YES"),
                ))),
                PrimitiveArg.Bytes(NsKeyedArchive.encode(NsKeyedArchive.array())),
                PrimitiveArg.Bytes(NsKeyedArchive.encode(options)),
            ),
        )
        if (reply.messageType == MSG_ERROR) {
            throw DtxException("ProcessControl returned an error")
        }
        if (reply.payload.isEmpty()) {
            throw DtxException("ProcessControl launch returned no PID")
        }
        return NsKeyedArchive.readRootInteger(reply.payload)
    }

    /**
     * Announces what this client supports, as Instruments does on connecting.
     *
     * The device sends its own capabilities unprompted and does not reply to ours, so this is
     * sent without expecting an answer.
     */
    private fun notifyCapabilities() {
        val selector = NsKeyedArchive.encode(
            NsKeyedArchive.text("_notifyOfPublishedCapabilities:"),
        )
        val capabilities = NsKeyedArchive.encode(
            NsKeyedArchive.dict(
                "com.apple.private.DTXConnection" to NsKeyedArchive.integer(1),
                "com.apple.private.DTXBlockCompression" to NsKeyedArchive.integer(2),
            ),
        )
        writeFrame(
            nextId(),
            0,
            0,
            false,
            selector,
            primitiveDictionary(PrimitiveArg.Bytes(capabilities)),
        )
    }

    private fun requestChannel(service: String): Int {
        val code = channelCode++
        val id = nextId()
        val selector = NsKeyedArchive.encode(NsKeyedArchive.text("_requestChannelWithCode:identifier:"))
        val serviceArchive = NsKeyedArchive.encode(NsKeyedArchive.text(service))
        val aux = primitiveDictionary(
            PrimitiveArg.Int32(code),
            PrimitiveArg.Bytes(serviceArchive),
        )
        writeFrame(id, 0, 0, true, selector, aux)
        val reply = readReply(id)
        if (reply.messageType == MSG_ERROR) throw DtxException("DTX channel request failed for $service")
        return code
    }

    private fun methodCall(channel: Int, selector: ByteArray, args: List<PrimitiveArg>): DtxReply {
        val id = nextId()
        val all = args
        val aux = if (all.isEmpty()) ByteArray(0) else primitiveDictionary(*all.toTypedArray())
        writeFrame(id, 0, channel, true, selector, aux)
        return readReply(id)
    }

    private fun readReply(targetId: Int): DtxReply {
        while (true) {
            val frame = readFrame()
            if (frame.identifier != targetId || frame.conversationIndex == 0) {
                if (frame.expectsReply) sendAck(frame)
                continue
            }
            return frame
        }
    }

    private fun sendAck(frame: DtxReply) {
        val id = frame.identifier
        val conversation = frame.conversationIndex + 1
        val wireChannel = if (conversation and 1 == 0) frame.channelCode else -frame.channelCode
        val payloadHeader = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(MSG_OK).putInt(0).putInt(0).putInt(0).array()
        writeRaw(
            encodeHeader(
                id, conversation, wireChannel, false, payloadHeader, ByteArray(0)
            )
        )
    }

    private fun nextId(): Int = identifier++

    private fun writeFrame(id: Int, conversation: Int, channel: Int, expectsReply: Boolean, payload: ByteArray, aux: ByteArray) {
        writeRaw(encodeHeader(id, conversation, channel, expectsReply, payload, aux))
    }

    private fun encodeHeader(id: Int, conversation: Int, channel: Int, expectsReply: Boolean, payload: ByteArray, aux: ByteArray): ByteArray {
        val auxSection = if (aux.isEmpty()) ByteArray(0) else {
            ByteBuffer.allocate(16 + aux.size).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(496).putInt(0).putInt(aux.size).putInt(0).put(aux).array()
        }
        val payloadLength = 16 + auxSection.size + payload.size
        val out = ByteBuffer.allocate(32 + payloadLength).order(ByteOrder.LITTLE_ENDIAN)
        out.order(ByteOrder.BIG_ENDIAN).putInt(DTX_MAGIC)
        out.order(ByteOrder.LITTLE_ENDIAN)
            .putInt(32).putShort(0).putShort(1).putInt(payloadLength)
            .putInt(id).putInt(conversation).putInt(channel).putInt(if (expectsReply) 1 else 0)
            .putInt(MSG_METHOD_INVOCATION).putInt(auxSection.size).putInt(auxSection.size + payload.size).putInt(0)
            .put(auxSection).put(payload)
        return out.array()
    }

    private fun primitiveDictionary(vararg args: PrimitiveArg): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (arg in args) {
            writeU32(out, T_NULL)
            when (arg) {
                is PrimitiveArg.Int32 -> { writeU32(out, T_UINT32); writeU32(out, arg.value) }
                is PrimitiveArg.Bytes -> { writeU32(out, T_BYTEARRAY); writeU32(out, arg.value.size); out.write(arg.value) }
            }
        }
        return out.toByteArray()
    }

    private fun readFrame(): DtxReply {
        val header = readExactly(32)
        val b = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val magic = b.int
        require(magic == DTX_MAGIC) { "bad DTX magic 0x${magic.toUInt().toString(16)}" }
        b.order(ByteOrder.LITTLE_ENDIAN)
        val headerLength = b.int
        require(headerLength == 32) { "unsupported DTX header length $headerLength" }
        val fragmentIndex = b.short.toInt() and 0xffff
        val fragmentCount = b.short.toInt() and 0xffff
        require(fragmentCount == 1 && fragmentIndex == 0) { "DTX fragmentation is not supported by this client" }
        val messageLength = b.int
        require(messageLength in 16..MAX_MESSAGE) { "invalid DTX message length $messageLength" }
        val identifier = b.int
        val conversation = b.int
        val channel = b.int
        val expectsReply = b.int != 0
        val body = readExactly(messageLength)
        val p = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)
        val type = p.int
        val auxLength = p.int
        val totalPayload = p.int
        p.int
        require(auxLength in 0..totalPayload && totalPayload == messageLength - 16) { "invalid DTX payload lengths" }
        val aux = if (auxLength == 0) 0 else {
            require(auxLength >= 16 && auxLength <= totalPayload) { "invalid DTX auxiliary length" }
            p.int; p.int; val declared = p.int; p.int
            require(declared <= auxLength - 16) { "invalid DTX auxiliary payload length" }
            p.position(p.position() + auxLength - 16)
            auxLength
        }
        val payloadLength = totalPayload - aux
        val payload = ByteArray(payloadLength)
        p.get(payload)
        return DtxReply(identifier, conversation, channel, expectsReply, type, payload)
    }

    private fun readExactly(count: Int): ByteArray {
        val out = ByteArray(count); var offset = 0
        while (offset < count) {
            val n = input.read(out, offset, count - offset)
            if (n < 0) throw EOFException("EOF in DTX frame")
            offset += n
        }
        return out
    }

    private fun writeRaw(bytes: ByteArray) { output.write(bytes); output.flush() }
    private fun writeU32(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write(value and 0xff); out.write((value ushr 8) and 0xff); out.write((value ushr 16) and 0xff); out.write((value ushr 24) and 0xff)
    }

    override fun close() { runCatching { input.close() }; runCatching { output.close() } }

    data class DtxReply(val identifier: Int, val conversationIndex: Int, val channelCode: Int, val expectsReply: Boolean, val messageType: Int, val payload: ByteArray)
    sealed interface PrimitiveArg {
        data class Int32(val value: Int) : PrimitiveArg
        data class Bytes(val value: ByteArray) : PrimitiveArg
    }
    class DtxException(message: String) : Exception(message)

    companion object {
        private const val DTX_MAGIC = 0x795B3D1F
        private const val MSG_OK = 0
        private const val MSG_METHOD_INVOCATION = 2
        private const val MSG_ERROR = 4
        private const val T_NULL = 0x0A
        private const val T_UINT32 = 0x03
        private const val T_BYTEARRAY = 0x02
        private const val MAX_MESSAGE = 128 * 1024 * 1024
    }
}
