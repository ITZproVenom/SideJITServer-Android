package dev.sidejit.coredevice

import dev.sidejit.core.serialization.ByteReader
import dev.sidejit.core.serialization.ByteWriter

/** Values that can travel in a RemoteXPC message body. */
sealed interface XpcValue {
    data object Null : XpcValue
    data class Bool(val value: Boolean) : XpcValue
    data class Int64(val value: Long) : XpcValue
    data class UInt64(val value: Long) : XpcValue
    data class Real(val value: Double) : XpcValue
    data class Date(val nanosSinceEpoch: Long) : XpcValue
    class Data(val value: ByteArray) : XpcValue {
        override fun equals(other: Any?) = other is Data && value.contentEquals(other.value)
        override fun hashCode() = value.contentHashCode()
    }
    data class Text(val value: String) : XpcValue
    data class Uuid(val bytes: List<Byte>) : XpcValue
    data class Arr(val items: List<XpcValue>) : XpcValue
    data class Dict(val entries: Map<String, XpcValue>) : XpcValue
}

class XpcException(message: String) : IllegalArgumentException(message)

/** Flag bits of the XPC wrapper header. */
object XpcFlags {
    const val ALWAYS_SET = 0x00000001
    const val DATA_PRESENT = 0x00000100
    const val WANTING_REPLY = 0x00010000
    const val REPLY = 0x00020000
    const val FILE_OPEN = 0x00100000
    const val INIT_HANDSHAKE = 0x00400000
}

data class XpcMessage(val flags: Int, val messageId: Long, val body: XpcValue?)

/**
 * RemoteXPC wire format: a 24 byte wrapper (`0x29b00b92`, flags, body length,
 * message id), then, when there is a body, `0x42133742`, version 5 and one
 * object. All integers are little endian; strings and blobs are padded to four
 * bytes.
 *
 * Implemented from the public description used by pymobiledevice3 and idevice;
 * not yet seen against a real device.
 */
object Xpc {
    const val WRAPPER_MAGIC = 0x29b00b92L
    const val BODY_MAGIC = 0x42133742L
    const val VERSION = 5L
    private const val MAX_DEPTH = 32
    private const val MAX_BODY = 32 * 1024 * 1024

    private const val T_NULL = 0x1000L
    private const val T_BOOL = 0x2000L
    private const val T_INT64 = 0x3000L
    private const val T_UINT64 = 0x4000L
    private const val T_REAL = 0x5000L
    private const val T_DATE = 0x7000L
    private const val T_DATA = 0x8000L
    private const val T_STRING = 0x9000L
    private const val T_UUID = 0xa000L
    private const val T_ARRAY = 0xe000L
    private const val T_DICT = 0xf000L

    fun encode(message: XpcMessage): ByteArray {
        val body = message.body?.let {
            ByteWriter().u32le(BODY_MAGIC).u32le(VERSION).also { w -> write(it, w) }.toByteArray()
        } ?: ByteArray(0)
        var flags = message.flags or XpcFlags.ALWAYS_SET
        if (message.body != null) flags = flags or XpcFlags.DATA_PRESENT
        return ByteWriter()
            .u32le(WRAPPER_MAGIC).u32le(flags.toLong() and 0xFFFFFFFFL)
            .u64le(body.size.toLong()).u64le(message.messageId)
            .bytes(body).toByteArray()
    }

    fun decode(bytes: ByteArray): XpcMessage {
        val r = ByteReader(bytes)
        try {
            if (r.u32le() != WRAPPER_MAGIC) throw XpcException("bad wrapper magic")
            val flags = r.u32le().toInt()
            val length = r.u64le()
            val id = r.u64le()
            if (length < 0 || length > MAX_BODY) throw XpcException("implausible body length $length")
            if (length == 0L) return XpcMessage(flags, id, null)
            if (r.remaining < length) throw XpcException("truncated body")
            if (r.u32le() != BODY_MAGIC) throw XpcException("bad body magic")
            if (r.u32le() != VERSION) throw XpcException("unsupported XPC version")
            return XpcMessage(flags, id, read(r, 0))
        } catch (e: ByteReader.TruncatedException) {
            throw XpcException("truncated message")
        }
    }

    private fun pad(n: Int) = (4 - n % 4) % 4

    private fun write(v: XpcValue, w: ByteWriter) {
        when (v) {
            XpcValue.Null -> w.u32le(T_NULL)
            is XpcValue.Bool -> w.u32le(T_BOOL).u32le(if (v.value) 1 else 0)
            is XpcValue.Int64 -> w.u32le(T_INT64).u64le(v.value)
            is XpcValue.UInt64 -> w.u32le(T_UINT64).u64le(v.value)
            is XpcValue.Real -> w.u32le(T_REAL).u64le(java.lang.Double.doubleToRawLongBits(v.value))
            is XpcValue.Date -> w.u32le(T_DATE).u64le(v.nanosSinceEpoch)
            is XpcValue.Data -> {
                w.u32le(T_DATA).u32le(v.value.size.toLong()).bytes(v.value)
                w.bytes(ByteArray(pad(v.value.size)))
            }
            is XpcValue.Text -> {
                val raw = v.value.toByteArray(Charsets.UTF_8) + 0
                w.u32le(T_STRING).u32le(raw.size.toLong()).bytes(raw).bytes(ByteArray(pad(raw.size)))
            }
            is XpcValue.Uuid -> {
                if (v.bytes.size != 16) throw XpcException("uuid must be 16 bytes")
                w.u32le(T_UUID).bytes(v.bytes.toByteArray())
            }
            is XpcValue.Arr -> {
                val inner = ByteWriter().u32le(v.items.size.toLong())
                v.items.forEach { write(it, inner) }
                val b = inner.toByteArray()
                w.u32le(T_ARRAY).u32le(b.size.toLong()).bytes(b)
            }
            is XpcValue.Dict -> {
                val inner = ByteWriter().u32le(v.entries.size.toLong())
                for ((k, value) in v.entries) {
                    val key = k.toByteArray(Charsets.UTF_8) + 0
                    inner.bytes(key).bytes(ByteArray(pad(key.size)))
                    write(value, inner)
                }
                val b = inner.toByteArray()
                w.u32le(T_DICT).u32le(b.size.toLong()).bytes(b)
            }
        }
    }

    private fun read(r: ByteReader, depth: Int): XpcValue {
        if (depth > MAX_DEPTH) throw XpcException("nesting too deep")
        return when (val type = r.u32le()) {
            T_NULL -> XpcValue.Null
            T_BOOL -> XpcValue.Bool(r.u32le() != 0L)
            T_INT64 -> XpcValue.Int64(r.u64le())
            T_UINT64 -> XpcValue.UInt64(r.u64le())
            T_REAL -> XpcValue.Real(java.lang.Double.longBitsToDouble(r.u64le()))
            T_DATE -> XpcValue.Date(r.u64le())
            T_DATA -> {
                val n = boundedLength(r)
                val data = r.bytes(n); r.skip(pad(n)); XpcValue.Data(data)
            }
            T_STRING -> {
                val n = boundedLength(r)
                val raw = r.bytes(n); r.skip(pad(n))
                XpcValue.Text(String(raw, 0, raw.indexOfFirst { it == 0.toByte() }.let { if (it < 0) raw.size else it }, Charsets.UTF_8))
            }
            T_UUID -> XpcValue.Uuid(r.bytes(16).toList())
            T_ARRAY -> {
                boundedLength(r)
                val count = boundedCount(r)
                XpcValue.Arr(List(count) { read(r, depth + 1) })
            }
            T_DICT -> {
                boundedLength(r)
                val count = boundedCount(r)
                val map = LinkedHashMap<String, XpcValue>()
                repeat(count) {
                    val key = StringBuilder()
                    var len = 0
                    while (true) {
                        val b = r.u8(); len++
                        if (b == 0) break
                        key.append(b.toChar())
                        if (len > 4096) throw XpcException("dictionary key too long")
                    }
                    r.skip(pad(len))
                    map[key.toString()] = read(r, depth + 1)
                }
                XpcValue.Dict(map)
            }
            else -> throw XpcException("unknown XPC type 0x${type.toString(16)}")
        }
    }

    private fun boundedLength(r: ByteReader): Int {
        val n = r.u32le()
        if (n < 0 || n > MAX_BODY || n > r.remaining) throw XpcException("bad length $n")
        return n.toInt()
    }

    private fun boundedCount(r: ByteReader): Int {
        val n = r.u32le()
        if (n < 0 || n > 1_000_000) throw XpcException("bad count $n")
        return n.toInt()
    }
}
