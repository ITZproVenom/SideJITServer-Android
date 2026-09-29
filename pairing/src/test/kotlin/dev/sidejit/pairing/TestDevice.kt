package dev.sidejit.pairing

import dev.sidejit.core.crypto.ChaChaPoly
import dev.sidejit.core.crypto.Digest
import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.Hkdf
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.Opack
import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.Tlv8
import dev.sidejit.core.serialization.jsonObject
import dev.sidejit.core.serialization.opack
import dev.sidejit.core.serialization.opackDict
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * A stand-in for the iPhone, written only for tests.
 *
 * It drives the same conversation an iOS device drives when it pairs into a pairable
 * host, so the accessory side can be exercised end to end without Apple hardware.
 * Passing these tests means the two implementations agree with each other; it does not
 * prove that a real device agrees. That needs a phone.
 */
class TestDevice(
    private val stream: RpPairingStream,
    private val setupCode: String,
    val name: String = "Test iPhone",
    val model: String = "iPhone17,1",
) {
    val identifier: String = UUID.randomUUID().toString().uppercase()
    val udid: String = UUID.randomUUID().toString().uppercase()
    val alternateIdentityKey: ByteArray = ByteArray(16) { (it + 1).toByte() }
    private val signingKey = Ed25519.generate()

    var accessoryIdentifier: String? = null
        private set
    var accessoryPublicKey: ByteArray? = null
        private set
    var accessorySignatureValid: Boolean = false
        private set
    lateinit var sessionKey: ByteArray
        private set

    fun handshake(attemptPairVerify: Boolean = false): JsonValue {
        stream.sendPlain(
            jsonObject(
                "request" to jsonObject(
                    "_0" to jsonObject(
                        "handshake" to jsonObject(
                            "_0" to jsonObject(
                                "hostOptions" to jsonObject(
                                    "attemptPairVerify" to JsonValue.of(attemptPairVerify),
                                ),
                                "wireProtocolVersion" to JsonValue.of(26),
                            ),
                        ),
                    ),
                ),
            ),
        )
        return stream.receivePlain()
    }

    private var salt: ByteArray = ByteArray(0)
    private var serverPublicKey: ByteArray = ByteArray(0)

    /** Sends M1 and reads M2. The host shows its setup code while this is in flight. */
    fun beginPairSetup() {
        sendTlv(Tlv8.Builder().add(PairingComponent.STATE, 1).add(PairingComponent.METHOD, 0).build())
        val m2 = receiveTlv()
        require(Tlv8.byte(m2, PairingComponent.STATE) == 2) { "expected M2" }
        salt = Tlv8.value(m2, PairingComponent.SALT)
        serverPublicKey = Tlv8.value(m2, PairingComponent.PUBLIC_KEY)
        require(serverPublicKey.size == 384) { "the host public key should be 384 bytes" }
        require(salt.size == 16) { "the host salt should be 16 bytes" }
    }

    /** Runs M3 through M6 with the code a person read off the host. */
    fun completePairSetup(code: String) {
        val srp = Srp(code)
        val proof = srp.proof(salt, serverPublicKey)
        sessionKey = srp.sessionKey
        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 3)
                .add(PairingComponent.PUBLIC_KEY, srp.publicKey)
                .add(PairingComponent.PROOF, proof)
                .build(),
        )

        val m4 = receiveTlv()
        require(Tlv8.byte(m4, PairingComponent.STATE) == 4) { "expected M4" }
        require(!Tlv8.contains(m4, PairingComponent.ERROR)) { "the host rejected the code" }
        val serverProof = Tlv8.value(m4, PairingComponent.PROOF)
        require(serverProof.contentEquals(srp.serverProof)) { "the host proof did not match" }

        val setupKey = derive("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
        val deviceX = derive("Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
        val publicKey = signingKey.publicKey
        val signature = signingKey.sign(deviceX + identifier.toByteArray(Charsets.UTF_8) + publicKey)
        val info = Opack.encode(
            opackDict(
                "altIRK" to alternateIdentityKey.opack(),
                "accountID" to identifier.opack(),
                "model" to model.opack(),
                "name" to name.opack(),
                "remotepairing_udid" to udid.opack(),
            ),
        )
        val plaintext = Tlv8.Builder()
            .add(PairingComponent.IDENTIFIER, identifier)
            .add(PairingComponent.PUBLIC_KEY, publicKey)
            .add(PairingComponent.SIGNATURE, signature)
            .add(PairingComponent.INFO, info)
            .build()
        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 5)
                .add(
                    PairingComponent.ENCRYPTED_DATA,
                    ChaChaPoly.seal(setupKey, ChaChaPoly.nonce("PS-Msg05"), plaintext),
                )
                .build(),
        )

        val m6 = receiveTlv()
        require(Tlv8.byte(m6, PairingComponent.STATE) == 6) { "expected M6" }
        val opened = ChaChaPoly.open(
            setupKey,
            ChaChaPoly.nonce("PS-Msg06"),
            Tlv8.value(m6, PairingComponent.ENCRYPTED_DATA),
        )
        val accessory = Tlv8.decode(opened)
        accessoryIdentifier = String(Tlv8.value(accessory, PairingComponent.IDENTIFIER), Charsets.UTF_8)
        accessoryPublicKey = Tlv8.value(accessory, PairingComponent.PUBLIC_KEY)
        val accessoryX = derive("Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
        accessorySignatureValid = Ed25519.verify(
            accessoryPublicKey!!,
            accessoryX + accessoryIdentifier!!.toByteArray(Charsets.UTF_8) + accessoryPublicKey!!,
            Tlv8.value(accessory, PairingComponent.SIGNATURE),
        )
    }

    /** Sends a proof derived from the wrong code, as a phone would after a typo. */
    fun completePairSetupWithWrongProof() {
        val srp = Srp(setupCode + "9")
        val proof = srp.proof(salt, serverPublicKey)
        sendTlv(
            Tlv8.Builder()
                .add(PairingComponent.STATE, 3)
                .add(PairingComponent.PUBLIC_KEY, srp.publicKey)
                .add(PairingComponent.PROOF, proof)
                .build(),
        )
    }

    fun receiveTlv(): List<Tlv8.Entry> {
        val message = stream.receivePlain()
        val encoded = requireNotNull(message.path("event", "_0", "pairingData", "_0", "data")?.asText) {
            "the host sent no pairing data"
        }
        return Tlv8.decode(Base64.getDecoder().decode(encoded))
    }

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

    private fun derive(salt: String, info: String): ByteArray = Hkdf.derive(
        Digest.SHA512,
        salt.toByteArray(Charsets.UTF_8),
        sessionKey,
        info.toByteArray(Charsets.UTF_8),
        32,
    )
}

/** The SRP-6a client half, written from the formulas for these tests only. */
private class Srp(private val password: String) {
    private val digest = Digest.SHA512
    private val n = BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
            "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
            "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
            "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        16,
    )
    private val g = BigInteger.valueOf(5)
    private val a = BigInteger(1, ByteArray(32).also { SecureRandom().nextBytes(it) })

    private fun unsigned(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        return if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
    }

    private fun pad(value: ByteArray): ByteArray {
        val out = ByteArray(384)
        System.arraycopy(value, 0, out, 384 - value.size, value.size)
        return out
    }

    val publicKey: ByteArray get() = unsigned(g.modPow(a, n))

    lateinit var sessionKey: ByteArray
        private set

    lateinit var serverProof: ByteArray
        private set

    fun proof(salt: ByteArray, serverPublicKey: ByteArray): ByteArray {
        val bPub = BigInteger(1, serverPublicKey)
        val k = BigInteger(1, digest.hash(unsigned(n), pad(unsigned(g))))
        val identity = digest.hash(
            "Pair-Setup".toByteArray(),
            byteArrayOf(':'.code.toByte()),
            password.toByteArray(),
        )
        val x = BigInteger(1, digest.hash(salt, identity))
        val aBytes = publicKey
        val u = BigInteger(1, digest.hash(aBytes, unsigned(bPub)))
        val premaster = bPub.subtract(k.multiply(g.modPow(x, n)).mod(n)).mod(n)
            .modPow(a.add(u.multiply(x)), n)
        sessionKey = digest.hash(unsigned(premaster))
        val nHash = digest.hash(unsigned(n))
        val gHash = digest.hash(unsigned(g))
        val xored = ByteArray(nHash.size) { (nHash[it].toInt() xor gHash[it].toInt()).toByte() }
        val m1 = digest.hash(
            xored,
            digest.hash("Pair-Setup".toByteArray()),
            salt,
            pad(aBytes),
            pad(unsigned(bPub)),
            sessionKey,
        )
        serverProof = digest.hash(aBytes, m1, sessionKey)
        return m1
    }
}