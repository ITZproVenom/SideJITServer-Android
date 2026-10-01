package dev.sidejit.pairing

import org.junit.Assert.assertEquals
import org.junit.Test

class SessionKeysTest {
    @Test
    fun `post-verify keys use the RPPairing main key derivation`() {
        val sharedSecret = ByteArray(32) { it.toByte() }
        val keys = SessionKeys.fromSharedSecret(sharedSecret)

        assertEquals(
            "df91c3c41e8d3901f7c525e250cb59237271d5a0202cdd8dd8bd3a4ade77bfe8",
            keys.readKey.hex(),
        )
        assertEquals(
            "9f8aa265911271e6d6e90daf564d82b5913d4b760373afbd6c03e675af681f8d",
            keys.writeKey.hex(),
        )
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
}
