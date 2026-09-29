package dev.sidejit.core.logging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RedactionTest {

    @Test
    fun `named secrets are removed`() {
        val text = "pairSetup privateKey=3f2a1b longTermSecretKey: abcdef"
        val result = Redaction.apply(text)
        assertFalse(result.contains("3f2a1b"))
        assertFalse(result.contains("abcdef"))
        assertTrue(result.contains("privateKey=<redacted>"))
    }

    @Test
    fun `long hex is removed`() {
        val key = "a".repeat(64)
        assertEquals("key material <redacted>", Redaction.apply("key material $key"))
    }

    @Test
    fun `setup codes are removed`() {
        assertEquals("show <pin> on the device", Redaction.apply("show 194823 on the device"))
    }

    @Test
    fun `ordinary numbers survive`() {
        assertEquals("port 62078 on 1 interface", Redaction.apply("port 62078 on 1 interface"))
    }

    @Test
    fun `short identifiers survive because they are not secret`() {
        val text = "device 00008120-001A2B3C4D5E6F70 udid short"
        assertEquals(text, Redaction.apply(text))
    }

    @Test
    fun `private key blocks are removed`() {
        val pem = "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----"
        assertEquals("<redacted key>", Redaction.apply(pem))
    }

    @Test
    fun `empty text is untouched`() {
        assertEquals("", Redaction.apply(""))
    }
}
