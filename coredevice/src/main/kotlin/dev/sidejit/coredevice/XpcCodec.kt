package dev.sidejit.coredevice

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/** Apple XPC binary message codec used by CoreDevice/RSD RemoteXPC. */
object XpcCodec {
    const val WRAPPER_MAGIC: Int = 0x29B00B92
    const val OBJECT_MAGIC: Int = 0x42133742
    const val BODY_VERSION: Int = 5

    const val FLAG_ALWAYS_SET: Int = 0x00000001
    const val FLAG_DATA: Int = 0x00000100
    const val FLAG_HEARTBEAT_REQUEST: Int = 0x00010000
    const val FLAG_HEARTBEAT_REPLY: Int = 0x00020000
    const val FLAG_FILE_OPEN: Int = 0x00100000
    const val FLAG_FILE_TX_STREAM_RESPONSE: Int = 0x00200000
    const val FLAG_INIT_HANDSHAKE: Int = 0x00400000

    private const val TYPE_NULL = 0x00001000
    private const val TYPE_BOOL = 0x00002000
    private const val TYPE_INT64 = 0x00003000
    private const val TYPE_UINT64 = 0x00004000
    private const val TYPE_DOUBLE = 0x00005000
    private const val TYPE_DATE = 0x00007000
    private const val TYPE_DATA = 0x00008000
    private const val TYPE_STRING = 0x00009000
    private const val TYPE_UUID = 0x0000A000
    private const val TYPE_ARRAY = 0x0000E000
    private const val TYPE_DICTIONARY = 0x0000F000
    private const val TYPE_FILE_TRANSFER = 0x0001A000
    private const val MAX_BODY = 8 * 1024 * 1024
    private const val MAX_DEPTH = 64
    private const val MAX_COLLECTION = 65_536

    data class Message(val flags: Int, val messageId: Long, val body: Value?)

    sealed interface Value {
        data object Null : Value
        data class Bool(val value: Boolean) : Value
        data class Int64Value(val value: Long) : Value
        data class UInt64Value(val value: Long) : Value
        data class DoubleValue(val value: Double) : Value
        data class DateValue(val value: Long) : Value
        data class DataValue(val value: ByteArray) : Value
        data class StringValue(val value: String) : Value
        data class UuidValue(val value: ByteArray) : Value
        data class ArrayValue(val items: List<Value>) : Value
        data class DictionaryValue(val entries: LinkedHashMap<String, Value>) : Value
        data class FileTransferValue(val messageId: Long, val data: Value) : Value
    }

    fun encode(message: Message): ByteArray {
        val body = ByteArrayOutputStream()
        message.body?.let {
            writeU32(body, OBJECT_MAGIC.toLong())
            writeU32(body, BODY_VERSION.toLong())
            encodeValue(it, body, 0)
        }
        val out = ByteArrayOutputStream(24 + body.size())
        writeU32(out, WRAPPER_MAGIC.toLong())
        writeU32(out, message.flags.toLong() and 0xFFFF_FFFFL)
        writeU64(out, body.size().toLong())
        writeU64(out, message.messageId)
        out.write(body.toByteArray())
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): Message {
        require(bytes.size >= 24) { "XPC wrapper truncated" }
        val r = Reader(bytes)
        require(r.u32().toInt() == WRAPPER_MAGIC) { "bad XPC wrapper magic" }
        val flags = r.u32().toInt()
        val bodyLen = r.u64()
        require(bodyLen <= MAX_BODY.toLong()) { "XPC body too large" }
        require(24L + bodyLen == bytes.size.toLong()) { "XPC length mismatch" }
        val messageId = r.u64()
        val body = if (bodyLen == 0L) null else {
            require(r.u32().toInt() == OBJECT_MAGIC) { "bad XPC object magic" }
            require(r.u32().toInt() == BODY_VERSION) { "bad XPC body version" }
            decodeValue(r, 0)
        }
        require(r.remaining() == 0) { "XPC trailing bytes" }
        return Message(flags, messageId, body)
    }

    private fun encodeValue(value: Value, out: ByteArrayOutputStream, depth: Int) {
        require(depth <= MAX_DEPTH) { "XPC nesting too deep" }
        when (value) {
            Value.Null -> writeU32(out, TYPE_NULL.toLong())
            is Value.Bool -> {
                writeU32(out, TYPE_BOOL.toLong())
                out.write(if (value.value) 1 else 0); out.write(0); out.write(0); out.write(0)
            }
            is Value.Int64Value -> { writeU32(out, TYPE_INT64.toLong()); writeU64(out, value.value) }
            is Value.UInt64Value -> { writeU32(out, TYPE_UINT64.toLong()); writeU64(out, value.value) }
            is Value.DoubleValue -> { writeU32(out, TYPE_DOUBLE.toLong()); writeU64(out, value.value.toBits()) }
            is Value.DateValue -> { writeU32(out, TYPE_DATE.toLong()); writeU64(out, value.value) }
            is Value.DataValue -> {
                require(value.value.size <= MAX_BODY) { "XPC data too large" }
                writeU32(out, TYPE_DATA.toLong()); writeU32(out, value.value.size.toLong())
                out.write(value.value); pad(out, value.value.size)
            }
            is Value.StringValue -> {
                val raw = value.value.toByteArray(StandardCharsets.UTF_8)
                require(raw.size + 1 <= MAX_BODY) { "XPC string too large" }
                writeU32(out, TYPE_STRING.toLong()); writeU32(out, (raw.size + 1).toLong())
                out.write(raw); out.write(0); pad(out, raw.size + 1)
            }
            is Value.UuidValue -> {
                require(value.value.size == 16) { "XPC UUID must be 16 bytes" }
                writeU32(out, TYPE_UUID.toLong()); out.write(value.value)
            }
            is Value.ArrayValue -> {
                require(value.items.size <= MAX_COLLECTION) { "XPC array too large" }
                val data = ByteArrayOutputStream(); writeU32(data, value.items.size.toLong())
                value.items.forEach { encodeValue(it, data, depth + 1) }
                writeU32(out, TYPE_ARRAY.toLong()); writeU32(out, data.size().toLong()); out.write(data.toByteArray())
            }
            is Value.DictionaryValue -> {
                require(value.entries.size <= MAX_COLLECTION) { "XPC dictionary too large" }
                val data = ByteArrayOutputStream(); writeU32(data, value.entries.size.toLong())
                for ((key, item) in value.entries) { encodeKey(key, data); encodeValue(item, data, depth + 1) }
                writeU32(out, TYPE_DICTIONARY.toLong()); writeU32(out, data.size().toLong()); out.write(data.toByteArray())
            }
            is Value.FileTransferValue -> {
                writeU32(out, TYPE_FILE_TRANSFER.toLong()); writeU64(out, value.messageId); encodeValue(value.data, out, depth + 1)
            }
        }
    }

    private fun decodeValue(r: Reader, depth: Int): Value {
        require(depth <= MAX_DEPTH) { "XPC nesting too deep" }
        return when (val type = r.u32().toInt()) {
            TYPE_NULL -> Value.Null
            TYPE_BOOL -> { require(r.remaining() >= 4) { "XPC bool truncated" }; val v = r.u8() != 0; r.skip(3); Value.Bool(v) }
            TYPE_INT64 -> Value.Int64Value(r.u64())
            TYPE_UINT64 -> Value.UInt64Value(r.u64())
            TYPE_DOUBLE -> Value.DoubleValue(Double.fromBits(r.u64()))
            TYPE_DATE -> Value.DateValue(r.u64())
            TYPE_DATA -> { val n = length(r.u32()); val p = align4(n); require(r.remaining() >= p); val v = r.bytes(n); r.skip(p - n); Value.DataValue(v) }
            TYPE_STRING -> { val n = length(r.u32()); require(n > 0); val p = align4(n); require(r.remaining() >= p); val raw = r.bytes(n); r.skip(p - n); val end = raw.indexOf(0).let { if (it < 0) n else it }; Value.StringValue(String(raw, 0, end, StandardCharsets.UTF_8)) }
            TYPE_UUID -> Value.UuidValue(r.bytes(16))
            TYPE_ARRAY -> {
                val n = length(r.u32()); require(n >= 4 && r.remaining() >= n); val sub = Reader(r.bytes(n));
                val count = collectionCount(sub.u32()); val items = ArrayList<Value>(count); repeat(count) { items += decodeValue(sub, depth + 1) };
                require(sub.remaining() == 0) { "XPC array trailing bytes" }; Value.ArrayValue(items)
            }
            TYPE_DICTIONARY -> {
                val n = length(r.u32()); require(n >= 4 && r.remaining() >= n); val sub = Reader(r.bytes(n));
                val count = collectionCount(sub.u32()); val map = LinkedHashMap<String, Value>(count)
                repeat(count) { map[decodeKey(sub)] = decodeValue(sub, depth + 1) };
                require(sub.remaining() == 0) { "XPC dictionary trailing bytes" }; Value.DictionaryValue(map)
            }
            TYPE_FILE_TRANSFER -> Value.FileTransferValue(r.u64(), decodeValue(r, depth + 1))
            else -> error("unknown XPC value type: $type")
        }
    }

    private fun encodeKey(key: String, out: ByteArrayOutputStream) { val raw = key.toByteArray(StandardCharsets.UTF_8); out.write(raw); out.write(0); pad(out, raw.size + 1) }
    private fun decodeKey(r: Reader): String {
        val start = r.position; while (r.remaining() > 0 && r.peek() != 0) r.skip(1)
        require(r.remaining() > 0) { "XPC key truncated" }; val raw = r.slice(start, r.position); r.skip(1)
        val total = raw.size + 1; r.skip(align4(total) - total); return String(raw, StandardCharsets.UTF_8)
    }
    private fun length(v: Long): Int { require(v in 0..MAX_BODY.toLong()) { "XPC value too large" }; return v.toInt() }
    private fun collectionCount(v: Long): Int { require(v in 0..MAX_COLLECTION.toLong()) { "XPC collection too large" }; return v.toInt() }
    private fun align4(v: Int): Int = (v + 3) and -4
    private fun pad(out: ByteArrayOutputStream, n: Int) { repeat(align4(n) - n) { out.write(0) } }
    private fun writeU32(out: ByteArrayOutputStream, v: Long) { for (i in 0 until 4) out.write(((v ushr (8 * i)) and 0xFF).toInt()) }
    private fun writeU64(out: ByteArrayOutputStream, v: Long) { for (i in 0 until 8) out.write(((v ushr (8 * i)) and 0xFF).toInt()) }

    private class Reader(private val data: ByteArray) {
        var position = 0; private set
        fun remaining() = data.size - position
        fun u8(): Int { require(remaining() >= 1); return data[position++].toInt() and 0xFF }
        fun u32(): Long { require(remaining() >= 4); var v = 0L; for (i in 0 until 4) v = v or ((data[position + i].toLong() and 0xFF) shl (8 * i)); position += 4; return v }
        fun u64(): Long { require(remaining() >= 8); var v = 0L; for (i in 0 until 8) v = v or ((data[position + i].toLong() and 0xFF) shl (8 * i)); position += 8; return v }
        fun bytes(n: Int): ByteArray { require(n >= 0 && remaining() >= n); val out = data.copyOfRange(position, position + n); position += n; return out }
        fun slice(start: Int, end: Int): ByteArray = data.copyOfRange(start, end)
        fun peek() = data[position].toInt() and 0xFF
        fun skip(n: Int) { require(n >= 0 && remaining() >= n); position += n }
    }
}
