package dev.sidejit.pairing

import dev.sidejit.core.serialization.Opack
import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.Tlv8

/** The iOS device on the other end, as it described itself during pair setup. */
data class PeerDevice(
    val accountId: String,
    val alternateIdentityKey: ByteArray,
    val model: String,
    val name: String,
    val udid: String,
    val identifier: String,
    val longTermPublicKey: ByteArray,
) {
    init {
        require(alternateIdentityKey.size == HostIdentity.ALT_IRK_BYTES) {
            "the peer alternate identity key must be 16 bytes"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PeerDevice && other.accountId == accountId && other.identifier == identifier &&
            other.alternateIdentityKey.contentEquals(alternateIdentityKey) &&
            other.longTermPublicKey.contentEquals(longTermPublicKey) &&
            other.model == model && other.name == name && other.udid == udid

    override fun hashCode(): Int = identifier.hashCode() * 31 + accountId.hashCode()

    companion object {
        /**
         * Reads the identity the device sends inside the encrypted M5 payload: its
         * identifier, long term public key and an OPACK information dictionary.
         */
        fun fromPairSetupTlv(entries: List<Tlv8.Entry>): PeerDevice {
            if (entries.contains(PairingComponent.ERROR)) {
                throw RpProtocolException("the device reported an error instead of its identity")
            }
            val identifier = entries.value(PairingComponent.IDENTIFIER)
            if (identifier.isEmpty()) throw RpProtocolException("the device identity had no identifier")
            val publicKey = entries.value(PairingComponent.PUBLIC_KEY)
            if (publicKey.isEmpty()) throw RpProtocolException("the device identity had no long term public key")
            val info = entries.value(PairingComponent.INFO)
            if (info.isEmpty()) throw RpProtocolException("the device identity had no information payload")
            val dictionary = Opack.decode(info).asDict
                ?: throw RpProtocolException("the device information payload was not a dictionary")

            fun text(key: String): String = dictionary[key]?.asText
                ?: throw RpProtocolException("the device information payload had no $key")

            val altIrk = dictionary["altIRK"]?.asBlob
                ?: throw RpProtocolException("the device information payload had no altIRK")
            if (altIrk.size != HostIdentity.ALT_IRK_BYTES) {
                throw RpProtocolException("the device altIRK was ${altIrk.size} bytes, expected 16")
            }
            return PeerDevice(
                accountId = text("accountID"),
                alternateIdentityKey = altIrk,
                model = text("model"),
                name = text("name"),
                udid = text("remotepairing_udid"),
                identifier = String(identifier, Charsets.UTF_8),
                longTermPublicKey = publicKey,
            )
        }
    }
}

private fun List<Tlv8.Entry>.value(component: PairingComponent): ByteArray =
    Tlv8.value(this, component)

private fun List<Tlv8.Entry>.contains(component: PairingComponent): Boolean =
    Tlv8.contains(this, component)

