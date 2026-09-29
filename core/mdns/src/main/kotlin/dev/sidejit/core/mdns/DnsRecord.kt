package dev.sidejit.core.mdns

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

object DnsType {
    const val A = 1
    const val PTR = 12
    const val TXT = 16
    const val AAAA = 28
    const val SRV = 33
    const val NSEC = 47
    const val ANY = 255
}

object DnsClass {
    const val IN = 1
    const val ANY = 255

    /** The top bit of the class field means "unicast reply requested" in a question. */
    const val UNICAST_RESPONSE = 0x8000

    /** The same bit in a resource record means "this is the whole truth, flush the rest". */
    const val CACHE_FLUSH = 0x8000
}

data class DnsQuestion(
    val name: DnsName,
    val type: Int,
    val unicastResponse: Boolean = false,
    val dnsClass: Int = DnsClass.IN,
) {
    fun matches(record: DnsRecord): Boolean {
        if (name != record.name) return false
        if (dnsClass != DnsClass.ANY && dnsClass != record.dnsClass) return false
        return type == DnsType.ANY || type == record.type
    }
}

sealed class DnsRecord {
    abstract val name: DnsName
    abstract val type: Int
    abstract val ttlSeconds: Long
    abstract val cacheFlush: Boolean
    open val dnsClass: Int get() = DnsClass.IN

    internal abstract fun writeData(writer: DnsWriter)

    data class Address(
        override val name: DnsName,
        val address: InetAddress,
        override val ttlSeconds: Long = 120,
        override val cacheFlush: Boolean = true,
    ) : DnsRecord() {
        override val type: Int get() = if (address is Inet6Address) DnsType.AAAA else DnsType.A

        override fun writeData(writer: DnsWriter) {
            writer.bytes(address.address)
        }
    }

    data class Pointer(
        override val name: DnsName,
        val target: DnsName,
        override val ttlSeconds: Long = 4500,
        override val cacheFlush: Boolean = false,
    ) : DnsRecord() {
        override val type: Int get() = DnsType.PTR

        override fun writeData(writer: DnsWriter) {
            writer.name(target)
        }
    }

    data class Service(
        override val name: DnsName,
        val target: DnsName,
        val port: Int,
        val priority: Int = 0,
        val weight: Int = 0,
        override val ttlSeconds: Long = 120,
        override val cacheFlush: Boolean = true,
    ) : DnsRecord() {
        override val type: Int get() = DnsType.SRV

        override fun writeData(writer: DnsWriter) {
            writer.u16(priority).u16(weight).u16(port).name(target)
        }
    }

    data class Text(
        override val name: DnsName,
        val entries: Map<String, String>,
        override val ttlSeconds: Long = 4500,
        override val cacheFlush: Boolean = true,
    ) : DnsRecord() {
        override val type: Int get() = DnsType.TXT

        override fun writeData(writer: DnsWriter) {
            if (entries.isEmpty()) {
                // An empty TXT record is a single zero length string, never zero bytes.
                writer.u8(0)
                return
            }
            for ((key, value) in entries) {
                val encoded = (if (value.isEmpty()) key else "$key=$value").toByteArray(Charsets.UTF_8)
                if (encoded.size > 255) throw DnsFormatException("a TXT entry may not exceed 255 bytes")
                writer.u8(encoded.size).bytes(encoded)
            }
        }
    }

    /** Anything we do not model. Kept so a message survives a round trip. */
    data class Opaque(
        override val name: DnsName,
        override val type: Int,
        val data: ByteArray,
        override val ttlSeconds: Long = 0,
        override val cacheFlush: Boolean = false,
        override val dnsClass: Int = DnsClass.IN,
    ) : DnsRecord() {
        override fun writeData(writer: DnsWriter) {
            writer.bytes(data)
        }

        override fun equals(other: Any?): Boolean =
            other is Opaque && other.name == name && other.type == type &&
                other.data.contentEquals(data) && other.ttlSeconds == ttlSeconds

        override fun hashCode(): Int =
            (name.hashCode() * 31 + type) * 31 + data.contentHashCode()
    }

    internal fun write(writer: DnsWriter) {
        writer.name(name)
        writer.u16(type)
        writer.u16(if (cacheFlush) dnsClass or DnsClass.CACHE_FLUSH else dnsClass)
        writer.u32(ttlSeconds)
        writer.lengthPrefixed { writeData(this) }
    }

    companion object {
        internal fun read(reader: DnsReader): DnsRecord {
            val name = reader.name()
            val type = reader.u16()
            val classField = reader.u16()
            val cacheFlush = classField and DnsClass.CACHE_FLUSH != 0
            val dnsClass = classField and 0x7FFF
            val ttl = reader.u32()
            val length = reader.u16()
            val end = reader.position + length
            val record = when (type) {
                DnsType.A -> if (length == 4) {
                    Address(name, InetAddress.getByAddress(reader.bytes(4)), ttl, cacheFlush)
                } else {
                    Opaque(name, type, reader.bytes(length), ttl, cacheFlush, dnsClass)
                }
                DnsType.AAAA -> if (length == 16) {
                    Address(name, InetAddress.getByAddress(reader.bytes(16)), ttl, cacheFlush)
                } else {
                    Opaque(name, type, reader.bytes(length), ttl, cacheFlush, dnsClass)
                }
                DnsType.PTR -> Pointer(name, reader.name(), ttl, cacheFlush)
                DnsType.SRV -> {
                    val priority = reader.u16()
                    val weight = reader.u16()
                    val port = reader.u16()
                    Service(name, reader.name(), port, priority, weight, ttl, cacheFlush)
                }
                DnsType.TXT -> {
                    val entries = LinkedHashMap<String, String>()
                    while (reader.position < end) {
                        val size = reader.u8()
                        if (reader.position + size > end) throw DnsFormatException("a TXT entry overruns its record")
                        val text = String(reader.bytes(size), Charsets.UTF_8)
                        if (text.isEmpty()) continue
                        val split = text.indexOf('=')
                        if (split < 0) entries[text] = "" else entries[text.substring(0, split)] = text.substring(split + 1)
                    }
                    Text(name, entries, ttl, cacheFlush)
                }
                else -> Opaque(name, type, reader.bytes(length), ttl, cacheFlush, dnsClass)
            }
            if (reader.position != end) {
                if (reader.position > end) throw DnsFormatException("a record overran its own length")
                reader.position = end
            }
            return record
        }
    }
}

/** An `Inet4Address` check that reads clearly at call sites. */
internal fun InetAddress.isIpv4(): Boolean = this is Inet4Address