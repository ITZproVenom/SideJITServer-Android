package dev.sidejit.pairing

import dev.sidejit.core.crypto.ChaChaPoly
import dev.sidejit.core.crypto.Digest
import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.Hkdf
import dev.sidejit.core.crypto.Srp6a
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.Opack
import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.PairingError
import dev.sidejit.core.serialization.Tlv8
import dev.sidejit.core.serialization.jsonObject
import dev.sidejit.core.serialization.opack
import dev.sidejit.core.serialization.opackDict
import java.security.SecureRandom
import java.util.Base64

/**
 * The accessory half of remote pairing, for the case where the iOS device initiates.
 *
 * Supports pair-setup (new pairing with a six-digit code) and, when a [PairingStore]
 * is supplied and the device asks for it, pair-verify against a stored record.
 */
class PairableHost(
    private val identity: HostIdentity,
    private val stream: RpPairingStream,
    private val store: PairingStore? = null,
    private val pinless: Boolean = false,
    private val random: SecureRandom = SecureRandom(),
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    var onSetupCode: (String) -> Unit = {}

    /**
     * Accept one connection. Returns either a fresh [PairingRecord] from setup or a
     * [VerifiedSession] from verify. The caller persists setup results via [store].
     */
    fun accept(): AcceptResult {
        val attemptVerify = handshake()
        return if (attemptVerify) {
            val store = this.store
                ?: throw RpProtocolException("the device asked to verify but no pairing store is configured")
            AcceptResult.Verified(PairVerify(identity, stream, store).verify())
        } else {
            val record = pairSetup()
            store?.save(record)
            AcceptResult.Setup(record)
        }
    }

    /** Backwards-compatible entry that only performs setup. */
    fun acceptSetup(): PairingRecord {
        handshake(forceSetup = true)
        return pairSetup().also { store?.save(it) }
    }

    private fun handshake(forceSetup: Boolean = false): Boolean {
        val request = stream.receivePlain()
        val handshake = request.path("request", "_0", "handshake", "_0")
            ?: throw RpProtocolException("the first message was not a handshake request")
        val attemptVerify = !forceSetup &&
            handshake.path("hostOptions", "attemptPairVerify")?.asBool == true

        if (attemptVerify && store == null) {
            throw RpProtocolException("the device asked to verify an existing pairing")
        }

        Log.i(
            LogTag.PAIRING,
            if (attemptVerify) "handshake: device wants pair-verify"
            else "handshake from a device, replying as a pairable host",
        )
        stream.sendPlain(
            jsonObject(
                "response" to jsonObject(
                    "forRequestIdentifier" to JsonValue.of(0),
                    "_1" to jsonObject(
                        "handshake" to jsonObject(
                            "_0" to jsonObject(
                                "wireProtocolVersion" to
                                    JsonValue.of(HostIdentity.WIRE_PROTOCOL_VERSION),
                                "minimumSupportedWireProtocolVersion" to JsonValue.of(8),
                                "deviceOptions" to jsonObject(
                                    "allowsPairSetup" to JsonValue.of(true),
                                    "allowsPinlessPairing" to JsonValue.of(pinless),
                                    "allowsIncomingTunnelConnections" to JsonValue.of(false),
                                    "allowsUpgradeOfLockdownPairings" to JsonValue.of(false),
                                    "allowsSharingSensitiveInfo" to JsonValue.of(false),
                                ),
                                "peerDeviceInfo" to jsonObject(
                                    "udid" to JsonValue.of(identity.udid),
                                    "deviceKVSIncludesSensitiveInfo" to JsonValue.of(false),
                                    "identifier" to JsonValue.of(identity.identifier),
                                    "name" to JsonValue.of(identity.name),
                                    "model" to JsonValue.of(identity.model),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
        return attemptVerify
    }

    private fun pairSetup(): PairingRecord {
        expectState(receiveTlv(), 1)

        val code = if (pinless) "000000" else "%06d".format(random.nextInt(1_000_000))
        val server = Srp6a.Server.create(code, random)
        onSetupCode(code)
        Log.i(LogTag.PAIRING, "pair setup started, waiting for the code to be entered")

        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 2)
                .add(PairingComponent.SALT, server.salt)
                .add(PairingComponent.PUBLIC_KEY, server.publicKey)
                .build(),
        )

        val m3 = receiveTlv()
        rejectError(m3)
        expectState(m3, 3)
        val devicePublicKey = Tlv8.value(m3, PairingComponent.PUBLIC_KEY)
        val deviceProof = Tlv8.value(m3, PairingComponent.PROOF)
        if (devicePublicKey.isEmpty() || deviceProof.isEmpty()) {
            throw RpProtocolException("pair setup M3 was missing the public key or the proof")
        }

        val session = server.respond(devicePublicKey)
        try {
            session.verifyClientProof(deviceProof)
        } catch (failure: Srp6a.AuthenticationFailure) {
            Log.w(LogTag.PAIRING, "the device proof did not match; the code was probably mistyped")
            sendTlv(
                Tlv8.Builder()
                    .add(PairingComponent.STATE, 4)
                    .add(PairingComponent.ERROR, PairingError.AUTHENTICATION.code)
                    .build(),
            )
            throw failure
        }

        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 4)
                .add(PairingComponent.PROOF, session.serverProof)
                .build(),
        )

        val setupKey = derive(session.sessionKey, ENCRYPT_SALT, ENCRYPT_INFO)

        val m5 = receiveTlv()
        rejectError(m5)
        expectState(m5, 5)
        val sealed = Tlv8.value(m5, PairingComponent.ENCRYPTED_DATA)
        if (sealed.isEmpty()) throw RpProtocolException("pair setup M5 carried no encrypted data")
        val plaintext = try {
            ChaChaPoly.open(setupKey, ChaChaPoly.nonce("PS-Msg05"), sealed)
        } catch (failure: ChaChaPoly.AuthenticationFailure) {
            throw RpProtocolException("pair setup M5 did not decrypt: ${failure.message}")
        }
        val deviceTlv = Tlv8.decode(plaintext)
        val peer = PeerDevice.fromPairSetupTlv(deviceTlv)
        verifyDeviceSignature(session.sessionKey, deviceTlv, peer)

        sendTlv(
            Tlv8.Builder()
                .add(
                    PairingComponent.ENCRYPTED_DATA,
                    ChaChaPoly.seal(
                        setupKey,
                        ChaChaPoly.nonce("PS-Msg06"),
                        accessoryIdentityTlv(session.sessionKey),
                    ),
                )
                .add(PairingComponent.STATE, 6)
                .build(),
        )

        Log.i(LogTag.PAIRING, "pair setup finished with ${peer.model}")
        return PairingRecord(peer, session.sessionKey, clockSeconds())
    }

    private fun accessoryIdentityTlv(sessionKey: ByteArray): ByteArray {
        val accessoryX = derive(sessionKey, ACCESSORY_SIGN_SALT, ACCESSORY_SIGN_INFO)
        val publicKey = identity.longTermPublicKey
        val signature = identity.signingKey.sign(
            accessoryX + identity.identifier.toByteArray(Charsets.UTF_8) + publicKey,
        )
        val info = Opack.encode(
            opackDict(
                "altIRK" to identity.alternateIdentityKey.opack(),
                "btAddr" to "00:00:00:00:00:00".opack(),
                "mac" to ByteArray(6).opack(),
                "remotepairing_serial_number" to SERIAL_NUMBER.opack(),
                "accountID" to identity.identifier.opack(),
                "remotepairing_udid" to identity.udid.opack(),
                "model" to identity.model.opack(),
                "name" to identity.name.opack(),
            ),
        )
        return Tlv8.Builder()
            .add(PairingComponent.IDENTIFIER, identity.identifier)
            .add(PairingComponent.PUBLIC_KEY, publicKey)
            .add(PairingComponent.SIGNATURE, signature)
            .add(PairingComponent.INFO, info)
            .build()
    }

    private fun verifyDeviceSignature(
        sessionKey: ByteArray,
        entries: List<Tlv8.Entry>,
        peer: PeerDevice,
    ) {
        val signature = Tlv8.value(entries, PairingComponent.SIGNATURE)
        if (signature.isEmpty()) {
            Log.w(LogTag.PAIRING, "the device identity carried no signature")
            return
        }
        val deviceX = derive(sessionKey, DEVICE_SIGN_SALT, DEVICE_SIGN_INFO)
        val signed = deviceX + peer.identifier.toByteArray(Charsets.UTF_8) + peer.longTermPublicKey
        if (peer.longTermPublicKey.size != Ed25519.PUBLIC_KEY_BYTES) {
            Log.w(LogTag.PAIRING, "the device long term key is not an Ed25519 key")
            return
        }
        if (Ed25519.verify(peer.longTermPublicKey, signed, signature)) {
            Log.d(LogTag.PAIRING, "the device identity signature checks out")
        } else {
            Log.w(LogTag.PAIRING, "the device identity signature did not verify")
        }
    }

    private fun derive(sessionKey: ByteArray, salt: String, info: String): ByteArray =
        Hkdf.derive(
            Digest.SHA512,
            salt.toByteArray(Charsets.UTF_8),
            sessionKey,
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
                                "kind" to JsonValue.of("setupManualPairing"),
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
            throw RpProtocolException("expected pair setup state $expected but got $state")
        }
    }

    private fun rejectError(entries: List<Tlv8.Entry>) {
        if (!Tlv8.contains(entries, PairingComponent.ERROR)) return
        val code = Tlv8.byte(entries, PairingComponent.ERROR)
        val named = code?.let { PairingError.of(it) }
        throw RpProtocolException("the device reported pairing error ${named ?: code}")
    }

    companion object {
        private const val ENCRYPT_SALT = "Pair-Setup-Encrypt-Salt"
        private const val ENCRYPT_INFO = "Pair-Setup-Encrypt-Info"
        private const val ACCESSORY_SIGN_SALT = "Pair-Setup-Accessory-Sign-Salt"
        private const val ACCESSORY_SIGN_INFO = "Pair-Setup-Accessory-Sign-Info"
        private const val DEVICE_SIGN_SALT = "Pair-Setup-Controller-Sign-Salt"
        private const val DEVICE_SIGN_INFO = "Pair-Setup-Controller-Sign-Info"
        private const val SERIAL_NUMBER = "AAAAAAAAAAAA"
    }
}

sealed class AcceptResult {
    data class Setup(val record: PairingRecord) : AcceptResult()
    data class Verified(val session: VerifiedSession) : AcceptResult()
}
