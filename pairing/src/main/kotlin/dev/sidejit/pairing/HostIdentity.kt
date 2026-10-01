package dev.sidejit.pairing

import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.SipHash
import dev.sidejit.core.serialization.ByteReader
import dev.sidejit.core.serialization.ByteWriter
import java.security.SecureRandom
import java.util.UUID

/**
 * Who this server says it is.
 *
 * An iOS device that has paired with us remembers the [identifier] and the long term
 * public key, so these values have to survive restarts. They are generated once and
 * then kept; regenerating them makes every existing pairing useless.
 */
class HostIdentity(
    /** A stable UUID. It is the mDNS instance name and the accessory identifier. */
    val identifier: String,
    /** The Ed25519 seed behind our long term signing key. Secret. */
    private val longTermSeed: ByteArray,
    /** The alternate identity resolving key, used for the mDNS `authTag`. Secret. */
    val alternateIdentityKey: ByteArray,
    /** A second stable UUID sent as `remotepairing_udid`. */
    val udid: String,
    /** What a person sees when the device offers to pair. */
    val name: String,
    /**
     * The model string sent during pairing. iOS decides what a peer is allowed to do
     * partly from this, and the remote pairing flow is a Mac to iPhone flow, so an
     * Android host has to present a Mac model identifier to be accepted at all.
     */
    val model: String,
) {
    init {
        require(longTermSeed.size == Ed25519.SEED_BYTES) { "the long term seed must be 32 bytes" }
        require(alternateIdentityKey.size == ALT_IRK_BYTES) { "the alternate identity key must be 16 bytes" }
        require(identifier.isNotBlank()) { "the identifier may not be blank" }
    }

    val signingKey: Ed25519.KeyPair get() = Ed25519.fromSeed(longTermSeed)

    val longTermPublicKey: ByteArray get() = signingKey.publicKey

    /** The `idevice-<eight hex digits>` host name the pairing flow advertises. */
    val mdnsHostName: String get() = "idevice-${identifier.take(8).lowercase()}"

    /** The TXT entries a device looks for in our advertisement. */
    fun mdnsTxtRecords(pinless: Boolean): Map<String, String> = linkedMapOf(
        "name" to name,
        "identifier" to identifier,
        "authTag" to SipHash.authTagBase64(alternateIdentityKey, identifier),
        "model" to model,
        "flags" to "0",
        "ver" to WIRE_PROTOCOL_VERSION.toString(),
        "minVer" to MINIMUM_WIRE_PROTOCOL_VERSION.toString(),
    ).also { if (pinless) it["pinless"] = "1" }

    fun encode(): ByteArray = ByteWriter().apply {
        u8(FORMAT_VERSION)
        text(identifier)
        blob(longTermSeed)
        blob(alternateIdentityKey)
        text(udid)
        text(name)
        text(model)
    }.toByteArray()

    companion object {
        const val ALT_IRK_BYTES: Int = 16

        /** The protocol version iOS 26 and 27 speak in the remote pairing handshake. */
        const val WIRE_PROTOCOL_VERSION: Int = 26
        const val MINIMUM_WIRE_PROTOCOL_VERSION: Int = 8

        private const val FORMAT_VERSION = 1

        fun generate(
            name: String,
            model: String = "Mac17,7",
            random: SecureRandom = SecureRandom(),
        ): HostIdentity = HostIdentity(
            identifier = UUID.randomUUID().toString().uppercase(),
            longTermSeed = ByteArray(Ed25519.SEED_BYTES).also(random::nextBytes),
            alternateIdentityKey = ByteArray(ALT_IRK_BYTES).also(random::nextBytes),
            udid = UUID.randomUUID().toString().uppercase(),
            name = name,
            model = model,
        )

        fun decode(data: ByteArray): HostIdentity {
            val reader = ByteReader(data)
            val version = reader.u8()
            require(version == FORMAT_VERSION) { "unknown host identity format $version" }
            return HostIdentity(
                identifier = reader.text(),
                longTermSeed = reader.blob(),
                alternateIdentityKey = reader.blob(),
                udid = reader.text(),
                name = reader.text(),
                model = reader.text(),
            )
        }
    }
}
