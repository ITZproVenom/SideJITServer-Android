package dev.sidejit.pairing

import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.jsonObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RpPairingStreamTest {
    private fun writer(): Pair<RpPairingStream, ByteArrayOutputStream> {
        val out = ByteArrayOutputStream()
        return RpPairingStream(ByteArrayInputStream(ByteArray(0)), out) to out
    }

    private fun reader(bytes: ByteArray): RpPairingStream =
        RpPairingStream(ByteArrayInputStream(bytes), ByteArrayOutputStream())

    @Test
    fun `a plain frame carries the magic, a big endian length and the envelope`() {
        val (stream, out) = writer()
        stream.sendPlain(jsonObject("hello" to JsonValue.of("world")))
        val frame = out.toByteArray()
        assertArrayEquals(RpPairingStream.MAGIC, frame.copyOfRange(0, 9))
        val length = ((frame[9].toInt() and 0xFF) shl 8) or (frame[10].toInt() and 0xFF)
        assertEquals(frame.size - 11, length)
        val body = String(frame, 11, length, Charsets.UTF_8)
        assertTrue(body, body.contains("\"originatedBy\":\"device\""))
        assertTrue(body, body.contains("\"sequenceNumber\":0"))
        assertTrue(body, body.contains("\"plain\":{\"_0\":{\"hello\":\"world\"}}"))
    }

    @Test
    fun `the sequence number advances with every message`() {
        val (stream, out) = writer()
        stream.sendPlain(JsonValue.Null)
        stream.sendPlain(JsonValue.Null)
        stream.sendEncrypted(byteArrayOf(1, 2, 3))
        val text = String(out.toByteArray(), Charsets.UTF_8)
        assertTrue(text.contains("\"sequenceNumber\":0"))
        assertTrue(text.contains("\"sequenceNumber\":1"))
        assertTrue(text.contains("\"sequenceNumber\":2"))
    }

    @Test
    fun `a plain frame round trips`() {
        val (stream, out) = writer()
        stream.sendPlain(jsonObject("a" to JsonValue.of(7)))
        val received = reader(out.toByteArray()).receive()
        assertEquals(7L, (received as RpMessage.Plain).value.path("a")?.asLong)
    }

    @Test
    fun `an encrypted frame round trips through base64`() {
        val (stream, out) = writer()
        val ciphertext = ByteArray(40) { it.toByte() }
        stream.sendEncrypted(ciphertext)
        val received = reader(out.toByteArray()).receive()
        assertArrayEquals(ciphertext, (received as RpMessage.Encrypted).ciphertext)
    }

    @Test(expected = RpProtocolException::class)
    fun `a frame with the wrong magic is refused`() {
        reader("NOTPAIRING".toByteArray() + byteArrayOf(0, 2, 0x7B, 0x7D)).receive()
    }

    @Test(expected = RpProtocolException::class)
    fun `a frame with malformed json is refused`() {
        val body = "{".toByteArray()
        reader(RpPairingStream.MAGIC + byteArrayOf(0, body.size.toByte()) + body).receive()
    }

    @Test(expected = RpProtocolException::class)
    fun `an envelope with neither message kind is refused`() {
        val body = "{\"message\":{}}".toByteArray()
        reader(RpPairingStream.MAGIC + byteArrayOf(0, body.size.toByte()) + body).receive()
    }

    @Test(expected = java.io.EOFException::class)
    fun `a truncated frame reports the end of the stream`() {
        reader(RpPairingStream.MAGIC + byteArrayOf(0, 40)).receive()
    }

    @Test(expected = RpProtocolException::class)
    fun `an encrypted message arriving where a plain one is expected is refused`() {
        val (stream, out) = writer()
        stream.sendEncrypted(byteArrayOf(1))
        reader(out.toByteArray()).receivePlain()
    }
}