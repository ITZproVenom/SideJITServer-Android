package dev.sidejit.pairing

import dev.sidejit.core.crypto.ChaChaPoly
import dev.sidejit.core.crypto.Digest
import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.Hkdf
import dev.sidejit.core.crypto.X25519
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.PairingError
import dev.sidejit.core.serialization.Tlv8
import dev.sidejit.core.serialization.jsonObject
import java.util.Base64

/**
 * Accessory-side pair-verify for a device that already holds a pairing record.
 *
 * After setup, the phone reconnects and asks to verify. Both sides run X25519,
 * the accessory signs the transcript with its long-term Ed25519 key, and the
 * shared secret becomes the pre-shared key material for the encrypted tunnel.
 *
 * This is the HomeKit pair-verify vocabulary reused by RPPairing. It has been
 * unit-tested against a local stand-in; it has never been run against a real
 * iPhone.
 */
class PairVerify(
    private val identity: HostIdentity,
    private val stream: RpPairingStream,
    private val store: PairingStore,
) {
    fun verify(): VerifiedSession {
        val m1 = receiveTlv()
        expectState(m1, 1)
        val devicePublic = Tlv8.value(m1, PairingComponent.PUBLIC_KEY)
        if (devicePublic.size != X25519.KEY_BYTES) {
            throw RpProtocolException("pair verify M1 public key was ${devicePublic.size} bytes, expected 32")
        }

        val ephemeral = X25519.generate()
        val sharedSecret = ephemeral.agree(devicePublic)
        val sessionKey = derive(sharedSecret, ENCRYPT_SALT, ENCRYPT_INFO)

        val accessoryInfo =
            ephemeral.publicKey + identity.identifier.toByteArray(Charsets.UTF_8) + devicePublic
        val signature = identity.signingKey.sign(accessoryInfo)
        val sealed = ChaChaPoly.seal(
            sessionKey,
            ChaChaPoly.nonce("PV-Msg02"),
            Tlv8.Builder()
                .add(PairingComponent.IDENTIFIER, identity.identifier)
                .add(PairingComponent.SIGNATURE, signature)
                .build(),
        )

        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 2)
                .add(PairingComponent.PUBLIC_KEY, ephemeral.publicKey)
                .add(PairingComponent.ENCRYPTED_DATA, sealed)
                .build(),
        )

        val m3 = receiveTlv()
        rejectError(m3)
        expectState(m3, 3)
        val deviceSealed = Tlv8.value(m3, PairingComponent.ENCRYPTED_DATA)
        if (deviceSealed.isEmpty()) {
            throw RpProtocolException("pair verify M3 carried no encrypted data")
        }
        val devicePlain = try {
            ChaChaPoly.open(sessionKey, ChaChaPoly.nonce("PV-Msg03"), deviceSealed)
        } catch (failure: ChaChaPoly.AuthenticationFailure) {
            sendAuthError(4)
            throw RpProtocolException("pair verify M3 did not decrypt: ${failure.message}")
        }
        val deviceTlv = Tlv8.decode(devicePlain)
        val peerIdentifier = String(Tlv8.value(deviceTlv, PairingComponent.IDENTIFIER), Charsets.UTF_8)
        val peerSignature = Tlv8.value(deviceTlv, PairingComponent.SIGNATURE)
        val record = store.load(peerIdentifier)
            ?: run {
                sendAuthError(4)
                throw RpProtocolException("no stored pairing for identifier $peerIdentifier")
            }

        val deviceInfo =
            devicePublic + peerIdentifier.toByteArray(Charsets.UTF_8) + ephemeral.publicKey
        if (!Ed25519.verify(record.peer.longTermPublicKey, deviceInfo, peerSignature)) {
            Log.w(LogTag.PAIRING, "pair verify device signature failed for $peerIdentifier")
            sendAuthError(4)
            throw RpProtocolException("pair verify device signature did not match")
        }

        sendTlv(Tlv8.Builder().add(PairingComponent.STATE, 4).build())

        val keys = SessionKeys.fromSharedSecret(sharedSecret)
        Log.i(LogTag.PAIRING, "pair verify finished with ${record.peer.model}")
        return VerifiedSession(record, keys, sharedSecret)
    }

    private fun sendAuthError(state: Int) {
        try {
            sendTlv(
                Tlv8.Builder()
                    .add(PairingComponent.STATE, state)
                    .add(PairingComponent.ERROR, PairingError.AUTHENTICATION.code)
                    .build(),
            )
        } catch (_: Exception) {
            // Best effort; the peer may already have closed.
        }
    }

    private fun derive(ikm: ByteArray, salt: String, info: String): ByteArray =
        Hkdf.derive(
            Digest.SHA512,
            salt.toByteArray(Charsets.UTF_8),
            ikm,
            info.toByteArray(Charsets.UTF_8),
            32,
        )

    private fun sendTlv(payload: ByteArray) {
        stream.sendPlain(
            jsonObject(
                "event" to jsonObject(
                    "_0" to jsonObject(
                        "pairingData" to jsonObject(
                            "_0" to jsonObject(
                                "data" to JsonValue.of(Base64.getEncoder().encodeToString(payload)),
                                "startNewSession" to JsonValue.of(false),
                                "kind" to JsonValue.of("verifyManualPairing"),
                            ),
                        ),
                    ),
                ),
            ),
        )
    }

    private fun receiveTlv(): List<Tlv8.Entry> {
        val message = stream.receivePlain()
        val encoded = message.path("event", "_0", "pairingData", "_0", "data")?.asText
            ?: throw RpProtocolException("the message carried no pairing data")
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (failure: IllegalArgumentException) {
            throw RpProtocolException("the pairing data was not base64")
        }
        return Tlv8.decode(bytes)
    }

    private fun expectState(entries: List<Tlv8.Entry>, expected: Int) {
        val state = Tlv8.byte(entries, PairingComponent.STATE)
        if (state != expected) {
            throw RpProtocolException("expected pair verify state $expected but got $state")
        }
    }

    private fun rejectError(entries: List<Tlv8.Entry>) {
        if (!Tlv8.contains(entries, PairingComponent.ERROR)) return
        val code = Tlv8.byte(entries, PairingComponent.ERROR)
        val named = code?.let { PairingError.of(it) }
        throw RpProtocolException("the device reported pairing error ${named ?: code}")
    }

    companion object {
        private const val ENCRYPT_SALT = "Pair-Verify-Encrypt-Salt"
        private const val ENCRYPT_INFO = "Pair-Verify-Encrypt-Info"
    }
}

/** Result of a successful pair-verify. */
data class VerifiedSession(
    val record: PairingRecord,
    val keys: SessionKeys,
    val sharedSecret: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is VerifiedSession &&
            other.record == record &&
            other.keys == keys &&
            other.sharedSecret.contentEquals(sharedSecret)

    override fun hashCode(): Int =
        record.hashCode() * 31 + keys.hashCode() * 31 + sharedSecret.contentHashCode()
}

/**
 * Control-channel session keys derived after pair-verify.
 * These are the inputs a later TLS-PSK / CoreDevice tunnel layer will consume.
 */
data class SessionKeys(
    val readKey: ByteArray,
    val writeKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is SessionKeys &&
            other.readKey.contentEquals(readKey) &&
            other.writeKey.contentEquals(writeKey)

    override fun hashCode(): Int = readKey.contentHashCode() * 31 + writeKey.contentHashCode()

    companion object {
        fun fromSharedSecret(sharedSecret: ByteArray): SessionKeys {
            // RPPairing's post-verify control channel uses an empty HKDF salt.
            // The host encrypts outgoing messages with ClientEncrypt-main and
            // decrypts incoming messages with ServerEncrypt-main.
            val read = Hkdf.derive(
                Digest.SHA512,
                ByteArray(0),
                sharedSecret,
                "ServerEncrypt-main".toByteArray(Charsets.UTF_8),
                32,
            )
            val write = Hkdf.derive(
                Digest.SHA512,
                ByteArray(0),
                sharedSecret,
                "ClientEncrypt-main".toByteArray(Charsets.UTF_8),
                32,
            )
            return SessionKeys(read, write)
        }
    }
}
