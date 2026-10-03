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
 * The initiating half of remote pairing: we dial the device's `_remotepairing._tcp` service and
 * verify an existing pairing.
 *
 * This is the mirror image of [PairVerify]. It matters which side initiates, because iOS only
 * serves `createListener` - the request that brings up a CoreDevice tunnel - on a connection the
 * host opened to the device. When the device dials into us we are the accessory and no tunnel
 * can be created, which is why pairing can look complete while JIT stays unavailable.
 *
 * Pair setup is not implemented here. Setup still happens through [PairableHost], because that
 * is the flow iOS drives from Settings.
 */
class RemotePairingClient(
    private val identity: HostIdentity,
    private val stream: RpPairingStream,
) {

    /** What the device told us about itself during the handshake. */
    data class Handshake(
        val wireProtocolVersion: Long?,
        val udid: String?,
        val identifier: String?,
        val name: String?,
        val model: String?,
        val allowsIncomingTunnelConnections: Boolean,
    )

    /**
     * Sends the handshake request and reads the device's reply.
     *
     * `attemptPairVerify` tells the device we hold a pairing record, so it should expect a verify
     * exchange rather than offering setup.
     */
    fun handshake(): Handshake {
        stream.sendPlain(
            jsonObject(
                "request" to jsonObject(
                    "_0" to jsonObject(
                        "handshake" to jsonObject(
                            "_0" to jsonObject(
                                "hostOptions" to jsonObject(
                                    "attemptPairVerify" to JsonValue.of(true),
                                ),
                                "wireProtocolVersion" to
                                    JsonValue.of(HostIdentity.WIRE_PROTOCOL_VERSION),
                            ),
                        ),
                    ),
                ),
            ),
        )

        val reply = stream.receivePlain()
        val body = reply.path("response", "_1", "handshake", "_0")
            ?: reply.path("response", "_0", "handshake", "_0")
            ?: throw RpProtocolException("the device did not answer the handshake")
        val info = body.path("peerDeviceInfo")
        val handshake = Handshake(
            wireProtocolVersion = body.path("wireProtocolVersion")?.asLong,
            udid = info?.path("udid")?.asText,
            identifier = info?.path("identifier")?.asText,
            name = info?.path("name")?.asText,
            model = info?.path("model")?.asText,
            allowsIncomingTunnelConnections =
                body.path("deviceOptions", "allowsIncomingTunnelConnections")?.asBool ?: false,
        )
        Log.i(
            LogTag.PAIRING,
            "handshake with ${handshake.name ?: "an unnamed device"} " +
                "(${handshake.model ?: "unknown model"}) wire ${handshake.wireProtocolVersion}",
        )
        return handshake
    }

    /**
     * Runs pair verify as the initiator against [record] and returns the session that the tunnel
     * layer consumes.
     */
    fun verify(record: PairingRecord): VerifiedSession {
        val ephemeral = X25519.generate()

        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 1)
                .add(PairingComponent.PUBLIC_KEY, ephemeral.publicKey)
                .build(),
            startNewSession = true,
        )

        val m2 = receiveTlv()
        rejectError(m2)
        expectState(m2, 2)
        val devicePublic = Tlv8.value(m2, PairingComponent.PUBLIC_KEY)
        if (devicePublic.size != X25519.KEY_BYTES) {
            throw RpProtocolException("pair verify M2 public key was ${devicePublic.size} bytes, expected 32")
        }
        val deviceSealed = Tlv8.value(m2, PairingComponent.ENCRYPTED_DATA)
        if (deviceSealed.isEmpty()) {
            throw RpProtocolException("pair verify M2 carried no encrypted data")
        }

        val sharedSecret = ephemeral.agree(devicePublic)
        val sessionKey = derive(sharedSecret)

        val devicePlain = try {
            ChaChaPoly.open(sessionKey, ChaChaPoly.nonce("PV-Msg02"), deviceSealed)
        } catch (failure: ChaChaPoly.AuthenticationFailure) {
            throw RpProtocolException("pair verify M2 did not decrypt: ${failure.message}")
        }
        val deviceTlv = Tlv8.decode(devicePlain)
        val deviceIdentifier = String(
            Tlv8.value(deviceTlv, PairingComponent.IDENTIFIER),
            Charsets.UTF_8,
        )
        val deviceSignature = Tlv8.value(deviceTlv, PairingComponent.SIGNATURE)
        val deviceInfo =
            devicePublic + deviceIdentifier.toByteArray(Charsets.UTF_8) + ephemeral.publicKey
        if (!Ed25519.verify(record.peer.longTermPublicKey, deviceInfo, deviceSignature)) {
            Log.w(LogTag.PAIRING, "pair verify signature from $deviceIdentifier did not match")
            throw RpProtocolException("pair verify device signature did not match")
        }

        val hostInfo =
            ephemeral.publicKey + identity.identifier.toByteArray(Charsets.UTF_8) + devicePublic
        val sealed = ChaChaPoly.seal(
            sessionKey,
            ChaChaPoly.nonce("PV-Msg03"),
            Tlv8.Builder()
                .add(PairingComponent.IDENTIFIER, identity.identifier)
                .add(PairingComponent.SIGNATURE, identity.signingKey.sign(hostInfo))
                .build(),
        )
        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 3)
                .add(PairingComponent.ENCRYPTED_DATA, sealed)
                .build(),
            startNewSession = false,
        )

        val m4 = receiveTlv()
        rejectError(m4)
        expectState(m4, 4)

        Log.i(LogTag.PAIRING, "pair verify finished as initiator with ${record.peer.name}")
        return VerifiedSession(record, SessionKeys.fromSharedSecret(sharedSecret), sharedSecret)
    }

    private fun derive(sharedSecret: ByteArray): ByteArray =
        Hkdf.derive(
            Digest.SHA512,
            ENCRYPT_SALT.toByteArray(Charsets.UTF_8),
            sharedSecret,
            ENCRYPT_INFO.toByteArray(Charsets.UTF_8),
            32,
        )

    private fun sendTlv(payload: ByteArray, startNewSession: Boolean) {
        stream.sendPlain(
            jsonObject(
                "event" to jsonObject(
                    "_0" to jsonObject(
                        "pairingData" to jsonObject(
                            "_0" to jsonObject(
                                "data" to JsonValue.of(Base64.getEncoder().encodeToString(payload)),
                                "startNewSession" to JsonValue.of(startNewSession),
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
        message.path("event", "_0", "pairingRejectedWithError")?.let {
            throw RpProtocolException("the device rejected pairing: ${it.encode()}")
        }
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
