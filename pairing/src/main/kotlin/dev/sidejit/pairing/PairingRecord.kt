package dev.sidejit.pairing

import dev.sidejit.core.serialization.ByteReader
import dev.sidejit.core.serialization.ByteWriter

/**
 * Everything that has to outlive the pairing conversation for a device to be usable
 * again later. The session key doubles as the pre shared key for the encrypted tunnel,
 * so this whole structure is secret and must be stored encrypted.
 */
data class PairingRecord(
    val peer: PeerDevice,
    val sessionKey: ByteArray,
    val establishedAtEpochSeconds: Long,
) {
    override fun equals(other: Any?): Boolean =
        other is PairingRecord && other.peer == peer &&
            other.sessionKey.contentEquals(sessionKey) &&
            other.establishedAtEpochSeconds == establishedAtEpochSeconds

    override fun hashCode(): Int = peer.hashCode() * 31 + sessionKey.contentHashCode()

    fun encode(): ByteArray = ByteWriter().apply {
        u8(FORMAT_VERSION)
        text(peer.accountId)
        blob(peer.alternateIdentityKey)
        text(peer.model)
        text(peer.name)
        text(peer.udid)
        text(peer.identifier)
        blob(peer.longTermPublicKey)
        blob(sessionKey)
        u64(establishedAtEpochSeconds)
    }.toByteArray()

    companion object {
        private const val FORMAT_VERSION = 1

        fun decode(data: ByteArray): PairingRecord {
            val reader = ByteReader(data)
            val version = reader.u8()
            require(version == FORMAT_VERSION) { "unknown pairing record format $version" }
            val peer = PeerDevice(
                accountId = reader.text(),
                alternateIdentityKey = reader.blob(),
                model = reader.text(),
                name = reader.text(),
                udid = reader.text(),
                identifier = reader.text(),
                longTermPublicKey = reader.blob(),
            )
            return PairingRecord(peer, reader.blob(), reader.u64())
        }
    }
}

/** Where pairing records live. The platform layer supplies an encrypted implementation. */
interface PairingStore {
    fun save(record: PairingRecord)
    fun load(identifier: String): PairingRecord?
    fun all(): List<PairingRecord>
    fun delete(identifier: String)
}

/** A store that keeps nothing. Useful in tests and when the platform has no storage. */
class InMemoryPairingStore : PairingStore {
    private val records = LinkedHashMap<String, PairingRecord>()

    override fun save(record: PairingRecord) {
        records[record.peer.identifier] = record
    }

    override fun load(identifier: String): PairingRecord? = records[identifier]

    override fun all(): List<PairingRecord> = records.values.toList()

    override fun delete(identifier: String) {
        records.remove(identifier)
    }
}

internal fun ByteWriter.text(value: String) = blob(value.toByteArray(Charsets.UTF_8))

internal fun ByteWriter.blob(value: ByteArray): ByteWriter {
    u16(value.size)
    return bytes(value)
}

internal fun ByteReader.text(): String = String(blob(), Charsets.UTF_8)

internal fun ByteReader.blob(): ByteArray = bytes(u16())