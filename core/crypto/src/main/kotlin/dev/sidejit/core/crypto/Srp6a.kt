package dev.sidejit.core.crypto

import java.math.BigInteger
import java.security.SecureRandom

/**
 * SRP-6a over the RFC 5054 3072 bit group with SHA-512.
 *
 * The pairable-host flow puts us on the server side: the iPhone is the SRP client and
 * proves that the user typed the PIN we display. The message formulas below follow the
 * implementation Apple's devices interoperate with, which differs from the letter of
 * RFC 5054 in two places, so they are spelled out rather than taken from a library:
 *
 *  - `u` is hashed over the unpadded big endian A and B,
 *  - `M1` is hashed over A and B left padded to the modulus length.
 */
object Srp6a {
    /** The identity the pairing protocol always uses. */
    const val USERNAME: String = "Pair-Setup"

    private val N: BigInteger = BigInteger(
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
    private val g: BigInteger = BigInteger.valueOf(5)
    private val digest = Digest.SHA512

    /** The modulus is 3072 bits, so every padded field is 384 bytes. */
    const val MODULUS_BYTES: Int = 384

    class AuthenticationFailure(message: String) : Exception(message)

    private fun unsigned(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        return if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
    }

    private fun pad(value: ByteArray): ByteArray {
        require(value.size <= MODULUS_BYTES) { "the value is wider than the modulus" }
        if (value.size == MODULUS_BYTES) return value
        val out = ByteArray(MODULUS_BYTES)
        System.arraycopy(value, 0, out, MODULUS_BYTES - value.size, value.size)
        return out
    }

    private val k: BigInteger by lazy {
        BigInteger(1, digest.hash(unsigned(N), pad(unsigned(g))))
    }

    /** v = g^H(salt | H(username | ":" | password)) mod N */
    fun verifier(username: String, password: String, salt: ByteArray): ByteArray {
        val identity = digest.hash(
            username.toByteArray(Charsets.UTF_8),
            byteArrayOf(':'.code.toByte()),
            password.toByteArray(Charsets.UTF_8),
        )
        val x = BigInteger(1, digest.hash(salt, identity))
        return unsigned(g.modPow(x, N))
    }

    /** The finished server side of one exchange. */
    class Session internal constructor(
        /** H(premaster secret); the pairing layer uses this as its session key. */
        val sessionKey: ByteArray,
        private val expectedClientProof: ByteArray,
        /** The proof we return to the device once its own proof checks out. */
        val serverProof: ByteArray,
    ) {
        fun verifyClientProof(proof: ByteArray) {
            if (!constantTimeEquals(proof, expectedClientProof)) {
                throw AuthenticationFailure("the device proof did not match, the PIN was probably wrong")
            }
        }
    }

    /**
     * The server side of the exchange. [privateKey] is our random `b`; keep it with the
     * [publicKey] we send in M2 and hand both back in [respond] when M3 arrives.
     */
    class Server(
        val salt: ByteArray,
        private val verifier: ByteArray,
        privateKey: ByteArray,
        private val username: String = USERNAME,
    ) {
        private val b: BigInteger = BigInteger(1, privateKey)
        private val v: BigInteger = BigInteger(1, verifier)
        private val bPub: BigInteger = ((k * v).mod(N) + g.modPow(b, N)).mod(N)

        /** B, always padded to the modulus length so the device sees a fixed size field. */
        val publicKey: ByteArray get() = pad(unsigned(bPub))

        fun respond(clientPublicKey: ByteArray): Session {
            val aPub = BigInteger(1, clientPublicKey)
            if (aPub.mod(N) == BigInteger.ZERO) {
                throw AuthenticationFailure("the device sent a degenerate public key")
            }
            val aBytes = unsigned(aPub)
            val bBytes = unsigned(bPub)
            val u = BigInteger(1, digest.hash(aBytes, bBytes))
            val premaster = (aPub * v.modPow(u, N)).mod(N).modPow(b, N)
            val sessionKey = digest.hash(unsigned(premaster))

            val nHash = digest.hash(unsigned(N))
            val gHash = digest.hash(unsigned(g))
            val xored = ByteArray(nHash.size) { (nHash[it].toInt() xor gHash[it].toInt()).toByte() }
            val m1 = digest.hash(
                xored,
                digest.hash(username.toByteArray(Charsets.UTF_8)),
                salt,
                pad(aBytes),
                pad(bBytes),
                sessionKey,
            )
            val m2 = digest.hash(aBytes, m1, sessionKey)
            return Session(sessionKey, m1, m2)
        }

        companion object {
            /**
             * Builds a server for [password], generating a fresh salt and private key.
             * The device expects B to be exactly 384 bytes, so retry until it is.
             */
            fun create(password: String, random: SecureRandom = SecureRandom()): Server {
                while (true) {
                    val salt = ByteArray(16).also(random::nextBytes)
                    val verifier = verifier(USERNAME, password, salt)
                    val privateKey = ByteArray(32).also(random::nextBytes)
                    val server = Server(salt, verifier, privateKey)
                    if (unsigned(server.bPub).size == MODULUS_BYTES) return server
                }
            }
        }
    }

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        for (index in left.indices) difference = difference or (left[index].toInt() xor right[index].toInt())
        return difference == 0
    }
}