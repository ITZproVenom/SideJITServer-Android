package dev.sidejit.core.serialization

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OpackTest {

    private fun roundTrip(value: OpackValue) {
        assertEquals(value, Opack.decode(Opack.encode(value)))
    }

    @Test
    fun `booleans are single bytes`() {
        assertArrayEquals(byteArrayOf(0x01), Opack.encode(true.opack()))
        assertArrayEquals(byteArrayOf(0x02), Opack.encode(false.opack()))
        roundTrip(true.opack())
        roundTrip(false.opack())
    }

    @Test
    fun `small integers live in the tag`() {
        assertArrayEquals(byteArrayOf(0x08), Opack.encode(0.opack()))
        assertArrayEquals(byteArrayOf(0x09), Opack.encode(1.opack()))
        assertArrayEquals(byteArrayOf(0x2F), Opack.encode(39.opack()))
        for (i in 0..39) roundTrip(i.opack())
    }

    @Test
    fun `larger integers are little endian`() {
        assertArrayEquals(byteArrayOf(0x30, 0x40), Opack.encode(64.opack()))
        assertArrayEquals(byteArrayOf(0x31, 0x34, 0x12), Opack.encode(0x1234.opack()))
        assertArrayEquals(
            byteArrayOf(0x32, 0xEF.toByte(), 0xBE.toByte(), 0xAD.toByte(), 0xDE.toByte()),
            Opack.encode(0xDEADBEEFL.opack())
        )
        roundTrip(64.opack())
        roundTrip(0x1234.opack())
        roundTrip(0xDEADBEEFL.opack())
        roundTrip(0x0102030405060708L.opack())
    }

    @Test
    fun `short text is inline`() {
        assertArrayEquals(byteArrayOf(0x43, 0x61, 0x62, 0x63), Opack.encode("abc".opack()))
        assertArrayEquals(byteArrayOf(0x40), Opack.encode("".opack()))
        roundTrip("abc".opack())
    }

    @Test
    fun `long text gets a length prefix`() {
        val text = "x".repeat(300)
        val encoded = Opack.encode(text.opack())
        assertEquals(0x62, encoded[0].toInt() and 0xFF)
        assertEquals(0x2C, encoded[1].toInt() and 0xFF) // 300 = 0x012C, low byte first
        assertEquals(0x01, encoded[2].toInt() and 0xFF)
        assertEquals(text, Opack.decode(encoded).asText)
    }

    @Test
    fun `text at the inline boundary uses the inline form`() {
        // 0x20 bytes is the last inline size; 0x21 must switch to a prefix.
        assertEquals(0x60, Opack.encode("y".repeat(0x20).opack())[0].toInt() and 0xFF)
        assertEquals(0x61, Opack.encode("y".repeat(0x21).opack())[0].toInt() and 0xFF)
        roundTrip("y".repeat(0x20).opack())
        roundTrip("y".repeat(0x21).opack())
    }

    @Test
    fun `blobs round trip at every size class`() {
        for (size in intArrayOf(0, 1, 0x20, 0x21, 255, 256, 70000)) {
            val blob = ByteArray(size) { (it and 0xFF).toByte() }
            assertArrayEquals(blob, Opack.decode(Opack.encode(blob.opack())).asBlob)
        }
    }

    @Test
    fun `reals keep their precision`() {
        assertEquals(0x35, Opack.encode(OpackValue.Real(1.5))[0].toInt() and 0xFF)
        assertEquals(0x36, Opack.encode(OpackValue.Real(0.1))[0].toInt() and 0xFF)
        roundTrip(OpackValue.Real(1.5))
        roundTrip(OpackValue.Real(0.1))
        roundTrip(OpackValue.Real(-2.25))
    }

    @Test
    fun `dictionaries and arrays nest`() {
        val value = opackDict(
            "name" to "Pixel".opack(),
            "port" to 49152.opack(),
            "flags" to OpackValue.Arr(listOf(1.opack(), true.opack(), "a".opack())),
            "nested" to opackDict("k" to byteArrayOf(1, 2, 3).opack()),
        )
        roundTrip(value)
        val decoded = Opack.decode(Opack.encode(value)).asDict!!
        assertEquals("Pixel", decoded["name"]?.asText)
        assertEquals(49152L, decoded["port"]?.asLong)
        assertEquals(3, decoded["flags"]?.asList?.size)
    }

    @Test
    fun `a large collection uses the terminated form`() {
        val entries = (0 until 20).associate { "k$it" to it.opack() }
        val encoded = Opack.encode(OpackValue.Dict(entries))
        assertEquals(0xEF, encoded[0].toInt() and 0xFF)
        assertEquals(0x03, encoded.last().toInt())
        assertEquals(20, Opack.decode(encoded).asDict?.size)

        val list = OpackValue.Arr((0 until 16).map { it.opack() })
        val encodedList = Opack.encode(list)
        assertEquals(0xDF, encodedList[0].toInt() and 0xFF)
        assertEquals(list, Opack.decode(encodedList))
    }

    @Test
    fun `a collection of exactly fourteen stays in the counted form`() {
        val entries = (0 until 14).associate { "k$it" to it.opack() }
        assertEquals(0xEE, Opack.encode(OpackValue.Dict(entries))[0].toInt() and 0xFF)
        roundTrip(OpackValue.Dict(entries))
    }

    @Test
    fun `back references from a device are resolved`() {
        // Built by hand the way a device sends it: two keys, the second value
        // pointing at the first string seen. Table order is name, Mac17,7,
        // model -- so index 1 is the repeated value.
        val bytes = byteArrayOf(
            0xE2.toByte(),
            0x44, 'n'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'e'.code.toByte(),
            0x47, 'M'.code.toByte(), 'a'.code.toByte(), 'c'.code.toByte(), '1'.code.toByte(),
            '7'.code.toByte(), ','.code.toByte(), '7'.code.toByte(),
            0x45, 'm'.code.toByte(), 'o'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte(),
            'l'.code.toByte(),
            0xA1.toByte(),
        )
        val decoded = Opack.decode(bytes).asDict!!
        assertEquals("Mac17,7", decoded["name"]?.asText)
        assertEquals("Mac17,7", decoded["model"]?.asText)
    }

    @Test
    fun `a repeated scalar is interned only once`() {
        // name, model and kind all share one value, so it occupies a single
        // table slot and index 0 is still the first key.
        val bytes = byteArrayOf(
            0xE2.toByte(),
            0x41, 'a'.code.toByte(),
            0x41, 'a'.code.toByte(),
            0x41, 'b'.code.toByte(),
            0xA0.toByte(),
        )
        val decoded = Opack.decode(bytes).asDict!!
        assertEquals("a", decoded["a"]?.asText)
        assertEquals("a", decoded["b"]?.asText)
    }

    @Test(expected = OpackException::class)
    fun `an out of range back reference is refused`() {
        Opack.decode(byteArrayOf(0xE1.toByte(), 0x41, 'a'.code.toByte(), 0xB0.toByte()))
    }

    @Test(expected = OpackException::class)
    fun `an unterminated dictionary is refused`() {
        Opack.decode(byteArrayOf(0xEF.toByte(), 0x41, 'a'.code.toByte(), 0x08))
    }

    @Test(expected = OpackException::class)
    fun `trailing bytes are refused`() {
        Opack.decode(byteArrayOf(0x01, 0x01))
    }

    @Test(expected = OpackException::class)
    fun `an unsupported tag is refused`() {
        Opack.decode(byteArrayOf(0x05))
    }

    @Test(expected = OpackException::class)
    fun `a non text dictionary key is refused`() {
        Opack.decode(byteArrayOf(0xE1.toByte(), 0x08, 0x08))
    }

    @Test
    fun `deep nesting is bounded rather than overflowing the stack`() {
        val bytes = ByteArray(200) { 0xD1.toByte() }
        val failure = runCatching { Opack.decode(bytes) }.exceptionOrNull()
        assertTrue("expected a controlled failure, got $failure", failure is OpackException)
    }
}
