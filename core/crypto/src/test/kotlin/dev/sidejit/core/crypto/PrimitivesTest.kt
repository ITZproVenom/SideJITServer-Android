package dev.sidejit.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

private fun String.unhex(): ByteArray {
    val clean = replace(" ", "").replace("\n", "")
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

class X25519Test {
    // RFC 7748 section 6.1.
    private val alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    private val alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    private val bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    private val bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    private val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    @Test
    fun `public keys match the rfc vectors`() {
        assertEquals(alicePublic, X25519.fromPrivateKey(alicePrivate.unhex()).publicKey.hex())
        assertEquals(bobPublic, X25519.fromPrivateKey(bobPrivate.unhex()).publicKey.hex())
    }

    @Test
    fun `both sides agree on the rfc shared secret`() {
        assertEquals(shared, X25519.fromPrivateKey(alicePrivate.unhex()).agree(bobPublic.unhex()).hex())
        assertEquals(shared, X25519.fromPrivateKey(bobPrivate.unhex()).agree(alicePublic.unhex()).hex())
    }

    @Test
    fun `generated pairs agree with each other`() {
        val first = X25519.generate()
        val second = X25519.generate()
        assertArrayEquals(first.agree(second.publicKey), second.agree(first.publicKey))
    }
}

class Ed25519Test {
    // RFC 8032 section 7.1, test vector 2.
    private val seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    private val publicKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    private val message = "72"
    private val signature =
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

    @Test
    fun `the public key derives from the rfc seed`() {
        assertEquals(publicKey, Ed25519.fromSeed(seed.unhex()).publicKey.hex())
    }

    @Test
    fun `signing reproduces the rfc signature`() {
        assertEquals(signature, Ed25519.fromSeed(seed.unhex()).sign(message.unhex()).hex())
    }

    @Test
    fun `verification accepts the rfc signature and rejects a tampered one`() {
        assertTrue(Ed25519.verify(publicKey.unhex(), message.unhex(), signature.unhex()))
        val tampered = signature.unhex().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(Ed25519.verify(publicKey.unhex(), message.unhex(), tampered))
        assertFalse(Ed25519.verify(publicKey.unhex(), "73".unhex(), signature.unhex()))
    }

    @Test
    fun `a wrong sized key is rejected rather than throwing`() {
        assertFalse(Ed25519.verify(ByteArray(31), message.unhex(), signature.unhex()))
        assertFalse(Ed25519.verify(publicKey.unhex(), message.unhex(), ByteArray(63)))
    }
}

class ChaChaPolyTest {
    // RFC 8439 section 2.8.2.
    private val key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    private val nonce = "070000004041424344454647"
    private val associatedData = "50515253c0c1c2c3c4c5c6c7"
    private val plaintext =
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069742e"
    private val expected =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116" +
            "1ae10b594f09e26a7e902ecbd0600691"

    @Test
    fun `sealing reproduces the rfc ciphertext and tag`() {
        val sealed = ChaChaPoly.seal(key.unhex(), nonce.unhex(), plaintext.unhex(), associatedData.unhex())
        assertEquals(expected, sealed.hex())
    }

    @Test
    fun `opening returns the original plaintext`() {
        val opened = ChaChaPoly.open(key.unhex(), nonce.unhex(), expected.unhex(), associatedData.unhex())
        assertEquals(plaintext, opened.hex())
    }

    @Test(expected = ChaChaPoly.AuthenticationFailure::class)
    fun `a modified ciphertext fails to open`() {
        val broken = expected.unhex().also { it[0] = (it[0] + 1).toByte() }
        ChaChaPoly.open(key.unhex(), nonce.unhex(), broken, associatedData.unhex())
    }

    @Test(expected = ChaChaPoly.AuthenticationFailure::class)
    fun `the wrong associated data fails to open`() {
        ChaChaPoly.open(key.unhex(), nonce.unhex(), expected.unhex(), ByteArray(0))
    }

    @Test(expected = ChaChaPoly.AuthenticationFailure::class)
    fun `a ciphertext shorter than the tag is refused`() {
        ChaChaPoly.open(key.unhex(), nonce.unhex(), ByteArray(4))
    }

    @Test
    fun `the labelled nonce puts the label at the end`() {
        assertEquals("0000000050532d4d73673035", ChaChaPoly.nonce("PS-Msg05").hex())
    }

    @Test
    fun `the RPPairing nonce puts the sequence first`() {
        assertEquals("000000000000000000000000", ChaChaPoly.rppairingNonce(0L).hex())
        assertEquals("010000000000000000000000", ChaChaPoly.rppairingNonce(1L).hex())
        assertEquals("ff0000000000000000000000", ChaChaPoly.rppairingNonce(255L).hex())
    }
}