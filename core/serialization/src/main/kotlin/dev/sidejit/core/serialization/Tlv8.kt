package dev.sidejit.core.serialization

/**
 * The component types carried inside a pairing message.
 *
 * These are the same numbers Apple's accessory pairing has used since HomeKit;
 * remote pairing reuses the vocabulary wholesale.
 */
enum class PairingComponent(val code: Int) {
    METHOD(0x00),
    IDENTIFIER(0x01),
    SALT(0x02),
    PUBLIC_KEY(0x03),
    PROOF(0x04),
    ENCRYPTED_DATA(0x05),
    STATE(0x06),
    ERROR(0x07),
    RETRY_DELAY(0x08),
    CERTIFICATE(0x09),
    SIGNATURE(0x0A),
    PERMISSIONS(0x0B),
    FRAGMENT_DATA(0x0C),
    FRAGMENT_LAST(0x0D),
    SESSION_ID(0x0E),
    TTL(0x0F),
    EXTRA_DATA(0x10),
    INFO(0x11),
    ACL(0x12),
    FLAGS(0x13),
    VALIDATION_DATA(0x14),
    MFI_AUTH_TOKEN(0x15),
    MFI_PRODUCT_TYPE(0x16),
    SERIAL_NUMBER(0x17),
    MFI_AUTH_TOKEN_UUID(0x18),
    APP_FLAGS(0x19),
    OWNERSHIP_PROOF(0x1A),
    SETUP_CODE_TYPE(0x1B),
    PRODUCTION_DATA(0x1C),
    APP_INFO(0x1D),
    SEPARATOR(0xFF),
    ;

    companion object {
        private val byCode = entries.associateBy { it.code }
        fun of(code: Int): PairingComponent? = byCode[code]
    }
}

/** The error codes a pairing peer can return in [PairingComponent.ERROR]. */
enum class PairingError(val code: Int) {
    UNKNOWN(0x01),
    AUTHENTICATION(0x02),
    BACKOFF(0x03),
    MAX_PEERS(0x04),
    MAX_TRIES(0x05),
    UNAVAILABLE(0x06),
    BUSY(0x07),
    ;

    companion object {
        private val byCode = entries.associateBy { it.code }
        fun of(code: Int): PairingError? = byCode[code]
    }
}

/**
 * Type-length-value triplets with a one-byte length.
 *
 * The one-byte length is the whole reason this needs care: a public key or an
 * encrypted blob is longer than 255 bytes, so a long value is split across
 * several entries of the same type which the reader joins back together. An
 * encoder that does not fragment produces a length byte that has silently
 * wrapped, and the peer sees a truncated key.
 */
object Tlv8 {

    const val MAX_FRAGMENT = 255

    data class Entry(val type: Int, val value: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Entry && other.type == type && other.value.contentEquals(value)

        override fun hashCode(): Int = 31 * type + value.contentHashCode()
    }

    fun encode(entries: List<Entry>): ByteArray {
        val writer = ByteWriter()
        for (entry in entries) {
            if (entry.value.isEmpty()) {
                writer.u8(entry.type).u8(0)
                continue
            }
            var offset = 0
            while (offset < entry.value.size) {
                val length = minOf(MAX_FRAGMENT, entry.value.size - offset)
                writer.u8(entry.type).u8(length)
                    .bytes(entry.value.copyOfRange(offset, offset + length))
                offset += length
            }
        }
        return writer.toByteArray()
    }

    fun decode(bytes: ByteArray): List<Entry> {
        val reader = ByteReader(bytes)
        val out = mutableListOf<Entry>()
        while (reader.remaining >= 2) {
            val type = reader.u8()
            val length = reader.u8()
            if (reader.remaining < length) {
                throw MalformedException(
                    "component 0x${type.toString(16)} claims $length bytes, ${reader.remaining} left"
                )
            }
            out += Entry(type, reader.bytes(length))
        }
        if (reader.hasMore) {
            throw MalformedException("${reader.remaining} trailing byte(s) after the last component")
        }
        return out
    }

    /**
     * Joins every fragment of one component, in order.
     *
     * Returns an empty array both when the component is absent and when it is
     * present but empty, which the protocol treats the same way; use
     * [contains] when the difference matters.
     */
    fun value(entries: List<Entry>, component: PairingComponent): ByteArray {
        val writer = ByteWriter()
        for (entry in entries) if (entry.type == component.code) writer.bytes(entry.value)
        return writer.toByteArray()
    }

    fun contains(entries: List<Entry>, component: PairingComponent): Boolean =
        entries.any { it.type == component.code }

    /** A single-byte component such as state or method. */
    fun byte(entries: List<Entry>, component: PairingComponent): Int? =
        entries.firstOrNull { it.type == component.code }
            ?.value?.takeIf { it.size == 1 }
            ?.let { it[0].toInt() and 0xFF }

    class Builder {
        private val entries = mutableListOf<Entry>()

        fun add(component: PairingComponent, value: ByteArray): Builder {
            entries += Entry(component.code, value)
            return this
        }

        fun add(component: PairingComponent, value: Int): Builder =
            add(component, byteArrayOf(value.toByte()))

        fun add(component: PairingComponent, value: String): Builder =
            add(component, value.toByteArray(Charsets.UTF_8))

        fun separator(): Builder = add(PairingComponent.SEPARATOR, ByteArray(0))

        fun build(): ByteArray = encode(entries)
    }

    class MalformedException(message: String) : IllegalArgumentException(message)
}
