package dev.sidejit.core.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

private fun String.unhex(): ByteArray {
    val clean = replace(" ", "").replace("\n", "")
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

class DigestsTest {
    @Test
    fun `sha512 of the empty input matches the published value`() {
        assertEquals(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            Digest.SHA512.hash(ByteArray(0)).hex(),
        )
    }

    @Test
    fun `hashing several parts equals hashing their concatenation`() {
        val joined = Digest.SHA256.hash("abcdef".toByteArray())
        val split = Digest.SHA256.hash("abc".toByteArray(), "def".toByteArray())
        assertEquals(joined.hex(), split.hex())
    }

    // RFC 5869 appendix A test case 1.
    @Test
    fun `hkdf matches rfc 5869 test case one`() {
        val output = Hkdf.derive(
            Digest.SHA256,
            salt = "000102030405060708090a0b0c".unhex(),
            inputKeyMaterial = "0b".repeat(22).unhex(),
            info = "f0f1f2f3f4f5f6f7f8f9".unhex(),
            length = 42,
        )
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            output.hex(),
        )
    }

    // RFC 5869 appendix A test case 2, the long input case.
    @Test
    fun `hkdf matches rfc 5869 test case two`() {
        val ikm = (0..79).joinToString("") { "%02x".format(it) }.unhex()
        val salt = (0x60..0xaf).joinToString("") { "%02x".format(it) }.unhex()
        val info = (0xb0..0xff).joinToString("") { "%02x".format(it) }.unhex()
        val output = Hkdf.derive(Digest.SHA256, salt, ikm, info, 82)
        assertEquals(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f1d87",
            output.hex(),
        )
    }

    // RFC 5869 appendix A test case 3, empty salt and info.
    @Test
    fun `hkdf matches rfc 5869 test case three`() {
        val output = Hkdf.derive(
            Digest.SHA256,
            salt = ByteArray(0),
            inputKeyMaterial = "0b".repeat(22).unhex(),
            info = ByteArray(0),
            length = 42,
        )
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            output.hex(),
        )
    }

    @Test
    fun `hmac sha512 matches rfc 4231 test case one`() {
        val mac = Hmac.compute(Digest.SHA512, "0b".repeat(20).unhex(), "Hi There".toByteArray())
        assertEquals(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            mac.hex(),
        )
    }
}