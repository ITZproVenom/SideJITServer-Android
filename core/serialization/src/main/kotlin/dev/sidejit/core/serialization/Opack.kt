package dev.sidejit.core.serialization

/**
 * A value in Apple's OPACK format.
 *
 * OPACK is what remote pairing puts on the wire instead of a property list:
 * the same shapes, encoded far more compactly, with a single byte doing the
 * work of a type tag and a small length at once.
 */
sealed interface OpackValue {

    data class Bool(val value: Boolean) : OpackValue

    /**
     * Integers are unsigned on the wire and up to 64 bits wide, so a value
     * above `Long.MAX_VALUE` arrives here as a negative [Long]. Nothing in
     * these protocols sends one, but it is worth knowing rather than
     * discovering.
     */
    data class Integer(val value: Long) : OpackValue

    data class Real(val value: Double) : OpackValue

    data class Text(val value: String) : OpackValue

    class Blob(val value: ByteArray) : OpackValue {
        override fun equals(other: Any?): Boolean = other is Blob && other.value.contentEquals(value)
        override fun hashCode(): Int = value.contentHashCode()
        override fun toString(): String = "Blob(${value.size} bytes)"
    }

    data class Arr(val values: List<OpackValue>) : OpackValue

    data class Dict(val entries: Map<String, OpackValue>) : OpackValue

    // Reading helpers. A protocol message is a dictionary nearly every time,
    // and the alternative is a cast at every use.
    val asDict: Map<String, OpackValue>? get() = (this as? Dict)?.entries
    val asText: String? get() = (this as? Text)?.value
    val asBlob: ByteArray? get() = (this as? Blob)?.value
    val asLong: Long? get() = (this as? Integer)?.value
    val asBool: Boolean? get() = (this as? Bool)?.value
    val asList: List<OpackValue>? get() = (this as? Arr)?.values
}

fun opackDict(vararg pairs: Pair<String, OpackValue>): OpackValue.Dict =
    OpackValue.Dict(linkedMapOf(*pairs))

fun String.opack(): OpackValue = OpackValue.Text(this)
fun ByteArray.opack(): OpackValue = OpackValue.Blob(this)
fun Long.opack(): OpackValue = OpackValue.Integer(this)
fun Int.opack(): OpackValue = OpackValue.Integer(toLong())
fun Boolean.opack(): OpackValue = OpackValue.Bool(this)

/**
 * OPACK encode and decode.
 *
 * Two details are easy to get wrong and both are load-bearing:
 *
 * Lengths and integers inside OPACK are **little-endian**, unlike every
 * network protocol wrapped around it.
 *
 * A real device uses **back-references**: once a scalar has appeared, a later
 * occurrence is a one-byte pointer into a table of everything seen so far. A
 * decoder that does not keep that table cannot read a message whose `name`
 * happens to equal its `model`, which devices really do send. The table
 * interns each distinct scalar once, in order of first appearance, and
 * collections are never interned. This encoder always writes literals, which
 * is valid, but the decoder must still build the table identically or every
 * index after the first repeat is wrong.
 */
object Opack {

    private const val TERMINATOR = 0x03

    fun encode(value: OpackValue): ByteArray {
        val writer = ByteWriter(128)
        write(value, writer)
        return writer.toByteArray()
    }

    fun decode(bytes: ByteArray): OpackValue {
        val reader = ByteReader(bytes)
        val table = mutableListOf<OpackValue>()
        val value = read(reader, table, 0)
        if (reader.hasMore) {
            throw OpackException("${reader.remaining} trailing byte(s) after the payload")
        }
        return value
    }

    // ---- writing ---------------------------------------------------------

    private fun write(value: OpackValue, out: ByteWriter) {
        when (value) {
            is OpackValue.Bool -> out.u8(if (value.value) 0x01 else 0x02)
            is OpackValue.Integer -> writeInteger(value.value, out)
            is OpackValue.Real -> writeReal(value.value, out)
            is OpackValue.Text -> writeSized(
                value.value.toByteArray(Charsets.UTF_8), 0x40, 0x61, out
            )
            is OpackValue.Blob -> writeSized(value.value, 0x70, 0x91, out)
            is OpackValue.Arr -> {
                val count = value.values.size
                out.u8(if (count < 15) 0xD0 + count else 0xDF)
                value.values.forEach { write(it, out) }
                if (count >= 15) out.u8(TERMINATOR)
            }
            is OpackValue.Dict -> {
                val count = value.entries.size
                out.u8(if (count < 15) 0xE0 + count else 0xEF)
                for ((key, entry) in value.entries) {
                    write(OpackValue.Text(key), out)
                    write(entry, out)
                }
                if (count >= 15) out.u8(TERMINATOR)
            }
        }
    }

    private fun writeInteger(value: Long, out: ByteWriter) {
        when {
            // 0x08..0x2F carry the value 0..39 in the tag itself.
            value in 0..0x27 -> out.u8((value + 8).toInt())
            value in 0..0xFF -> out.u8(0x30).u8(value.toInt())
            value in 0..0xFFFF -> out.u8(0x31).u16le(value.toInt())
            value in 0..0xFFFFFFFFL -> out.u8(0x32).u32le(value)
            else -> out.u8(0x33).u64le(value)
        }
    }

    private fun writeReal(value: Double, out: ByteWriter) {
        val asFloat = value.toFloat()
        if (asFloat.toDouble() == value) {
            out.u8(0x35).u32le(java.lang.Float.floatToRawIntBits(asFloat).toLong() and 0xFFFFFFFFL)
        } else {
            out.u8(0x36).u64le(java.lang.Double.doubleToRawLongBits(value))
        }
    }

    private fun writeSized(bytes: ByteArray, inlineBase: Int, sizeBase: Int, out: ByteWriter) {
        val length = bytes.size
        when {
            length <= 0x20 -> out.u8(inlineBase + length)
            length <= 0xFF -> out.u8(sizeBase).u8(length)
            length <= 0xFFFF -> out.u8(sizeBase + 1).u16le(length)
            else -> out.u8(sizeBase + 2).u32le(length.toLong())
        }
        out.bytes(bytes)
    }

    // ---- reading ---------------------------------------------------------

    private const val MAX_DEPTH = 32

    private fun read(reader: ByteReader, table: MutableList<OpackValue>, depth: Int): OpackValue {
        if (depth > MAX_DEPTH) throw OpackException("nested more than $MAX_DEPTH deep")
        val tag = reader.u8()
        return when (tag) {
            0x01 -> OpackValue.Bool(true)
            0x02 -> OpackValue.Bool(false)
            TERMINATOR -> throw OpackException("unexpected terminator")
            in 0x08..0x2F -> OpackValue.Integer((tag - 8).toLong())
            0x30 -> intern(table, OpackValue.Integer(reader.u8().toLong()))
            0x31 -> intern(table, OpackValue.Integer(reader.u16le().toLong()))
            0x32 -> intern(table, OpackValue.Integer(reader.u32le()))
            0x33 -> intern(table, OpackValue.Integer(reader.u64le()))
            0x35 -> intern(
                table,
                OpackValue.Real(
                    java.lang.Float.intBitsToFloat(reader.u32le().toInt()).toDouble()
                )
            )
            0x36 -> intern(
                table,
                OpackValue.Real(java.lang.Double.longBitsToDouble(reader.u64le()))
            )
            in 0x40..0x64 -> intern(
                table,
                OpackValue.Text(
                    String(reader.bytes(sizedLength(tag, 0x40, 0x61, reader)), Charsets.UTF_8)
                )
            )
            in 0x70..0x94 -> intern(
                table,
                OpackValue.Blob(reader.bytes(sizedLength(tag, 0x70, 0x91, reader)))
            )
            in 0xA0..0xC0 -> lookup(table, tag - 0xA0)
            0xC1 -> lookup(table, reader.u8())
            0xC2 -> lookup(table, reader.u16le())
            0xC3 -> lookup(table, boundedIndex(reader.u32le()))
            0xC4 -> lookup(table, boundedIndex(reader.u64le()))
            in 0xD0..0xDE -> readArray(reader, table, depth, tag - 0xD0)
            0xDF -> readArray(reader, table, depth, null)
            in 0xE0..0xEE -> readDict(reader, table, depth, tag - 0xE0)
            0xEF -> readDict(reader, table, depth, null)
            else -> throw OpackException("unsupported tag 0x${tag.toString(16)}")
        }
    }

    private fun readArray(
        reader: ByteReader,
        table: MutableList<OpackValue>,
        depth: Int,
        count: Int?,
    ): OpackValue {
        val values = mutableListOf<OpackValue>()
        if (count != null) {
            repeat(count) { values += read(reader, table, depth + 1) }
        } else {
            while (true) {
                if (!reader.hasMore) throw OpackException("array is not terminated")
                if (reader.peekU8() == TERMINATOR) {
                    reader.u8()
                    break
                }
                values += read(reader, table, depth + 1)
            }
        }
        return OpackValue.Arr(values)
    }

    private fun readDict(
        reader: ByteReader,
        table: MutableList<OpackValue>,
        depth: Int,
        count: Int?,
    ): OpackValue {
        val entries = LinkedHashMap<String, OpackValue>()
        fun pair() {
            val key = read(reader, table, depth + 1)
            val name = key.asText
                ?: throw OpackException("dictionary key was ${key::class.simpleName}, not text")
            entries[name] = read(reader, table, depth + 1)
        }
        if (count != null) {
            repeat(count) { pair() }
        } else {
            while (true) {
                if (!reader.hasMore) throw OpackException("dictionary is not terminated")
                if (reader.peekU8() == TERMINATOR) {
                    reader.u8()
                    break
                }
                pair()
            }
        }
        return OpackValue.Dict(entries)
    }

    private fun sizedLength(tag: Int, inlineBase: Int, sizeBase: Int, reader: ByteReader): Int =
        when {
            tag in inlineBase until sizeBase -> tag - inlineBase
            tag == sizeBase -> reader.u8()
            tag == sizeBase + 1 -> reader.u16le()
            tag == sizeBase + 2 -> boundedIndex(reader.u32le())
            tag == sizeBase + 3 -> boundedIndex(reader.u64le())
            else -> throw OpackException("unsupported length tag 0x${tag.toString(16)}")
        }

    private fun boundedIndex(value: Long): Int {
        if (value < 0 || value > Int.MAX_VALUE) throw OpackException("length $value is out of range")
        return value.toInt()
    }

    private fun intern(table: MutableList<OpackValue>, value: OpackValue): OpackValue {
        if (!table.contains(value)) table += value
        return value
    }

    private fun lookup(table: List<OpackValue>, index: Int): OpackValue =
        table.getOrNull(index)
            ?: throw OpackException("back-reference $index, only ${table.size} seen so far")
}

class OpackException(message: String) : IllegalArgumentException(message)
