package dev.sidejit.core.crypto

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Test

class SipHashTest {
    private val referenceKey = ByteArray(16) { it.toByte() }

    // The vector table published with the SipHash paper: the key 00..0f hashed over
    // inputs of length zero through fifteen whose bytes count up from zero.
    @Test
    fun `the published reference vectors reproduce`() {
        val expected = listOf(
            "726fdb47dd0e0e31",
            "74f839c593dc67fd",
            "0d6c8009d9a94f5a",
            "85676696d7fb7e2d",
            "cf2794e0277187b7",
            "18765564cd99a68d",
            "cbc9466e58fee3ce",
            "ab0200f58b01d137",
            "93f5f5799a932462",
            "9e0082df0ba9e4b0",
            "7a5dbbc594ddb9f3",
            "f4b32f46226bada7",
            "751e8fbc860ee5fb",
            "14ea5627c0843d90",
            "f723ca908e7af2ee",
            "a129ca6149be45e5",
        )
        for (length in expected.indices) {
            val message = ByteArray(length) { it.toByte() }
            assertEquals(
                expected[length],
                java.lang.Long.toHexString(SipHash.hash24(referenceKey, message)).padStart(16, '0'),
            )
        }
    }

    @Test
    fun `the auth tag matches a capture from a real advertisement`() {
        val altIrk = Base64.getDecoder().decode("Mgp6ZGPzXM2ku9br46vsiw==")
        val identifier = "2BE6E510-0325-4365-923E-B14C6F57DB3A"
        assertEquals("kXjlTr2l", SipHash.authTagBase64(altIrk, identifier))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a wrong sized key is refused`() {
        SipHash.hash24(ByteArray(8), ByteArray(0))
    }
}

/**
 * The published vectors are given as the little endian byte string of the result, so
 * they are read back the same way rather than as a plain hexadecimal number.
 */
private fun String.toLong16(): Long {
    var value = 0L
    for (index in 0 until 8) {
        val byte = substring(index * 2, index * 2 + 2).toLong(16)
        value = value or (byte shl (8 * index))
    }
    return value
}