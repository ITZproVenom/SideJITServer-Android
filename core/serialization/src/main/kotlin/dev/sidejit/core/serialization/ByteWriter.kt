package dev.sidejit.core.serialization

import java.io.ByteArrayOutputStream

/** Builds structured bytes. The mirror of [ByteReader]. */
class ByteWriter(initialCapacity: Int = 64) {

    private val buffer = ByteArrayOutputStream(initialCapacity)

    val size: Int get() = buffer.size()

    fun u8(value: Int): ByteWriter {
        buffer.write(value and 0xFF)
        return this
    }

    fun u16(value: Int): ByteWriter {
        buffer.write((value ushr 8) and 0xFF)
        buffer.write(value and 0xFF)
        return this
    }

    fun u16le(value: Int): ByteWriter {
        buffer.write(value and 0xFF)
        buffer.write((value ushr 8) and 0xFF)
        return this
    }

    fun u32(value: Long): ByteWriter {
        for (shift in 24 downTo 0 step 8) buffer.write(((value ushr shift) and 0xFF).toInt())
        return this
    }

    fun u32le(value: Long): ByteWriter {
        for (shift in 0..24 step 8) buffer.write(((value ushr shift) and 0xFF).toInt())
        return this
    }

    fun u64(value: Long): ByteWriter {
        for (shift in 56 downTo 0 step 8) buffer.write(((value ushr shift) and 0xFF).toInt())
        return this
    }

    fun u64le(value: Long): ByteWriter {
        for (shift in 0..56 step 8) buffer.write(((value ushr shift) and 0xFF).toInt())
        return this
    }

    fun bytes(value: ByteArray): ByteWriter {
        buffer.write(value, 0, value.size)
        return this
    }

    fun utf8(value: String): ByteWriter = bytes(value.toByteArray(Charsets.UTF_8))

    fun toByteArray(): ByteArray = buffer.toByteArray()
}
