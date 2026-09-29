package dev.sidejit.core.mdns

import java.io.ByteArrayOutputStream

/** Thrown when a packet cannot be parsed. Multicast traffic is untrusted input. */
class DnsFormatException(message: String) : Exception(message)

/**
 * A domain name as a list of labels, without the trailing empty root label.
 * Comparison is case insensitive, as DNS requires.
 */
data class DnsName(val labels: List<String>) {
    constructor(dotted: String) : this(
        dotted.trim('.').let { if (it.isEmpty()) emptyList() else it.split('.') },
    )

    val dotted: String get() = if (labels.isEmpty()) "." else labels.joinToString(".") + "."

    override fun toString(): String = dotted

    override fun equals(other: Any?): Boolean {
        if (other !is DnsName) return false
        if (other.labels.size != labels.size) return false
        return labels.indices.all { labels[it].equals(other.labels[it], ignoreCase = true) }
    }

    override fun hashCode(): Int = labels.fold(7) { acc, label -> acc * 31 + label.lowercase().hashCode() }

    fun endsWith(suffix: DnsName): Boolean {
        if (suffix.labels.size > labels.size) return false
        val offset = labels.size - suffix.labels.size
        return suffix.labels.indices.all { labels[offset + it].equals(suffix.labels[it], ignoreCase = true) }
    }
}

/**
 * Writes DNS wire format, reusing earlier names through compression pointers.
 * One writer serialises one message; the offsets it remembers are message relative.
 */
class DnsWriter {
    private val out = ByteArrayOutputStream()
    private val nameOffsets = HashMap<String, Int>()

    val size: Int get() = out.size()

    fun u8(value: Int) = apply { out.write(value and 0xFF) }

    fun u16(value: Int) = apply {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    fun u32(value: Long) = apply {
        for (shift in intArrayOf(24, 16, 8, 0)) out.write(((value ushr shift) and 0xFF).toInt())
    }

    fun bytes(value: ByteArray) = apply { out.write(value, 0, value.size) }

    fun name(name: DnsName) = apply {
        var remaining = name.labels
        while (remaining.isNotEmpty()) {
            val key = remaining.joinToString(".") { it.lowercase() }
            val known = nameOffsets[key]
            if (known != null) {
                u16(0xC000 or known)
                return@apply
            }
            // Only offsets that fit in fourteen bits can be pointed at.
            if (out.size() < 0x3FFF) nameOffsets[key] = out.size()
            val label = remaining.first().toByteArray(Charsets.UTF_8)
            if (label.isEmpty()) throw DnsFormatException("an empty label cannot be encoded")
            if (label.size > 63) throw DnsFormatException("a label may not exceed 63 bytes")
            u8(label.size)
            bytes(label)
            remaining = remaining.drop(1)
        }
        u8(0)
    }

    /** Writes a length prefixed block, filling in the 16 bit length afterwards. */
    fun lengthPrefixed(body: DnsWriter.() -> Unit) = apply {
        val placeholder = out.size()
        u16(0)
        val start = out.size()
        body()
        val length = out.size() - start
        val array = out.toByteArray()
        array[placeholder] = ((length ushr 8) and 0xFF).toByte()
        array[placeholder + 1] = (length and 0xFF).toByte()
        out.reset()
        out.write(array, 0, array.size)
    }

    fun toByteArray(): ByteArray = out.toByteArray()
}

/** Reads DNS wire format, following compression pointers without looping forever. */
class DnsReader(private val data: ByteArray, var position: Int = 0) {
    val remaining: Int get() = data.size - position

    private fun require(count: Int) {
        if (remaining < count) throw DnsFormatException("the packet ended early")
    }

    fun u8(): Int {
        require(1)
        return data[position++].toInt() and 0xFF
    }

    fun u16(): Int = (u8() shl 8) or u8()

    fun u32(): Long = (u16().toLong() shl 16) or u16().toLong()

    fun bytes(count: Int): ByteArray {
        require(count)
        return data.copyOfRange(position, position + count).also { position += count }
    }

    fun name(): DnsName {
        val labels = ArrayList<String>()
        var cursor = position
        var jumped = false
        var jumps = 0
        while (true) {
            if (cursor >= data.size) throw DnsFormatException("a name ran past the end of the packet")
            val length = data[cursor].toInt() and 0xFF
            when {
                length == 0 -> {
                    cursor++
                    if (!jumped) position = cursor
                    return DnsName(labels)
                }
                length and 0xC0 == 0xC0 -> {
                    if (cursor + 1 >= data.size) throw DnsFormatException("a truncated compression pointer")
                    val target = ((length and 0x3F) shl 8) or (data[cursor + 1].toInt() and 0xFF)
                    if (!jumped) position = cursor + 2
                    jumped = true
                    if (++jumps > 32) throw DnsFormatException("too many compression pointers")
                    if (target >= data.size) throw DnsFormatException("a compression pointer past the end")
                    cursor = target
                }
                length and 0xC0 != 0 -> throw DnsFormatException("an unsupported label type")
                else -> {
                    if (cursor + 1 + length > data.size) {
                        throw DnsFormatException("a label ran past the end of the packet")
                    }
                    labels.add(String(data, cursor + 1, length, Charsets.UTF_8))
                    cursor += 1 + length
                    if (labels.size > 128) throw DnsFormatException("a name with too many labels")
                }
            }
        }
    }
}