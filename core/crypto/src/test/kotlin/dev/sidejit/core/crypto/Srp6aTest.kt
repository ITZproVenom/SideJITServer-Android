package dev.sidejit.core.crypto

import java.math.BigInteger
import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A minimal SRP-6a client written only for these tests. It stands in for the iPhone so
 * the server side can be exercised end to end without any Apple hardware. It is written
 * from the formulas directly rather than reusing the production code, so agreement
 * between the two is evidence rather than a tautology.
 */
private class TestClient(private val password: String) {
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
            Srp6a.USERNAME.toByteArray(),
            byteArrayOf(':'.code.toByte()),
            password.toByteArray(),
        )
        val x = BigInteger(1, digest.hash(salt, identity))
        val aBytes = unsigned(g.modPow(a, n))
        val u = BigInteger(1, digest.hash(aBytes, unsigned(bPub)))
        val premaster = bPub.subtract(k.multiply(g.modPow(x, n)).mod(n)).mod(n)
            .modPow(a.add(u.multiply(x)), n)
        sessionKey = digest.hash(unsigned(premaster))
        val nHash = digest.hash(unsigned(n))
        val gHash = digest.hash(unsigned(g))
        val xored = ByteArray(nHash.size) { (nHash[it].toInt() xor gHash[it].toInt()).toByte() }
        val m1 = digest.hash(
            xored,
            digest.hash(Srp6a.USERNAME.toByteArray()),
            salt,
            pad(aBytes),
            pad(unsigned(bPub)),
            sessionKey,
        )
        serverProof = digest.hash(aBytes, m1, sessionKey)
        return m1
    }
}

class Srp6aTest {
    @Test
    fun `a matching pin produces the same session key on both sides`() {
        val server = Srp6a.Server.create("314159")
        val client = TestClient("314159")
        val session = server.respond(client.publicKey)
        val clientProof = client.proof(server.salt, server.publicKey)
        session.verifyClientProof(clientProof)
        assertArrayEquals(client.sessionKey, session.sessionKey)
        assertArrayEquals(client.serverProof, session.serverProof)
        assertEquals(64, session.sessionKey.size)
    }

    @Test(expected = Srp6a.AuthenticationFailure::class)
    fun `a wrong pin is rejected`() {
        val server = Srp6a.Server.create("314159")
        val client = TestClient("271828")
        val session = server.respond(client.publicKey)
        session.verifyClientProof(client.proof(server.salt, server.publicKey))
    }

    @Test(expected = Srp6a.AuthenticationFailure::class)
    fun `a degenerate client public key is refused`() {
        val server = Srp6a.Server.create("000000")
        server.respond(ByteArray(384))
    }

    @Test
    fun `the server public key is always the full modulus width`() {
        repeat(4) { assertEquals(384, Srp6a.Server.create("000000").publicKey.size) }
    }

    @Test
    fun `the verifier is deterministic for a given salt`() {
        val salt = ByteArray(16) { it.toByte() }
        assertArrayEquals(
            Srp6a.verifier(Srp6a.USERNAME, "123456", salt),
            Srp6a.verifier(Srp6a.USERNAME, "123456", salt),
        )
    }
}