package dev.sidejit.core.serialization

/**
 * Reads structured bytes off a buffer, refusing to read past the end.
 *
 * Every one of these protocols is length-prefixed somewhere, and a length
 * field arriving from the network is a number somebody else chose. Bounds are
 * checked on every read so a hostile or simply truncated frame produces a
 * clear exception at the point of the bad field, rather than an
 * `ArrayIndexOutOfBoundsException` from four layers down.
 */
class ByteReader(private val source: ByteArray, private var offset: Int = 0) {

    val position: Int get() = offset
    val remaining: Int get() = source.size - offset
    val hasMore: Boolean get() = remaining > 0

    fun seek(to: Int) {
        require(to in 0..source.size) { "cannot seek to $to in ${source.size} bytes" }
        offset = to
    }

    fun skip(count: Int) {
        require(count >= 0) { "cannot skip backwards" }
        need(count)
        offset += count
    }

    fun u8(): Int {
        need(1)
        return source[offset++].toInt() and 0xFF
    }

    fun i8(): Byte {
        need(1)
        return source[offset++]
    }

    fun u16(): Int {
        need(2)
        val value = ((source[offset].toInt() and 0xFF) shl 8) or (source[offset + 1].toInt() and 0xFF)
        offset += 2
        return value
    }

    fun u16le(): Int {
        need(2)
        val value = (source[offset].toInt() and 0xFF) or ((source[offset + 1].toInt() and 0xFF) shl 8)
        offset += 2
        return value
    }

    fun u32(): Long {
        need(4)
        var value = 0L
        for (i in 0 until 4) value = (value shl 8) or (source[offset + i].toLong() and 0xFF)
        offset += 4
        return value
    }

    fun u32le(): Long {
        need(4)
        var value = 0L
        for (i in 3 downTo 0) value = (value shl 8) or (source[offset + i].toLong() and 0xFF)
        offset += 4
        return value
    }

    fun u64(): Long {
        need(8)
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (source[offset + i].toLong() and 0xFF)
        offset += 8
        return value
    }

    fun u64le(): Long {
        need(8)
        var value = 0L
        for (i in 7 downTo 0) value = (value shl 8) or (source[offset + i].toLong() and 0xFF)
        offset += 8
        return value
    }

    fun bytes(count: Int): ByteArray {
        require(count >= 0) { "cannot read $count bytes" }
        need(count)
        val out = source.copyOfRange(offset, offset + count)
        offset += count
        return out
    }

    fun rest(): ByteArray = bytes(remaining)

    /** Peeks without consuming, for formats that dispatch on a type byte. */
    fun peekU8(): Int {
        need(1)
        return source[offset].toInt() and 0xFF
    }

    fun utf8(count: Int): String = String(bytes(count), Charsets.UTF_8)

    private fun need(count: Int) {
        if (remaining < count) {
            throw TruncatedException(
                "wanted $count bytes at $offset but only $remaining remain"
            )
        }
    }

    class TruncatedException(message: String) : IllegalArgumentException(message)
}
