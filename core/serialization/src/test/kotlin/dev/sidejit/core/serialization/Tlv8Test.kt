package dev.sidejit.core.serialization

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Tlv8Test {

    @Test
    fun `short entries encode as type length value`() {
        val bytes = Tlv8.Builder()
            .add(PairingComponent.STATE, 1)
            .add(PairingComponent.METHOD, 0)
            .build()
        assertArrayEquals(byteArrayOf(0x06, 0x01, 0x01, 0x00, 0x01, 0x00), bytes)
    }

    @Test
    fun `an empty component keeps its zero length`() {
        assertArrayEquals(byteArrayOf(0xFF.toByte(), 0x00), Tlv8.Builder().separator().build())
    }

    @Test
    fun `a long value is fragmented and rejoined`() {
        val key = ByteArray(600) { (it % 251).toByte() }
        val bytes = Tlv8.Builder().add(PairingComponent.PUBLIC_KEY, key).build()

        // 600 bytes needs three entries: 255, 255, 90, each with a 2-byte head.
        assertEquals(600 + 3 * 2, bytes.size)
        val entries = Tlv8.decode(bytes)
        assertEquals(3, entries.size)
        assertEquals(255, entries[0].value.size)
        assertEquals(255, entries[1].value.size)
        assertEquals(90, entries[2].value.size)
        assertArrayEquals(key, Tlv8.value(entries, PairingComponent.PUBLIC_KEY))
    }

    @Test
    fun `an exact multiple of the fragment size does not gain an empty entry`() {
        val value = ByteArray(510) { 7 }
        val entries = Tlv8.decode(Tlv8.Builder().add(PairingComponent.ENCRYPTED_DATA, value).build())
        assertEquals(2, entries.size)
        assertArrayEquals(value, Tlv8.value(entries, PairingComponent.ENCRYPTED_DATA))
    }

    @Test
    fun `unknown component types survive decoding`() {
        // A newer iOS adding a component must not make the whole message
        // unreadable, so decoding keeps the raw type.
        val entries = Tlv8.decode(byteArrayOf(0x7E, 0x01, 0x42))
        assertEquals(1, entries.size)
        assertEquals(0x7E, entries.single().type)
        assertNull(PairingComponent.of(0x7E))
    }

    @Test(expected = Tlv8.MalformedException::class)
    fun `a length past the end is refused`() {
        Tlv8.decode(byteArrayOf(0x03, 0x10, 0x01, 0x02))
    }

    @Test(expected = Tlv8.MalformedException::class)
    fun `a trailing stray byte is refused`() {
        Tlv8.decode(byteArrayOf(0x06, 0x01, 0x01, 0x06))
    }

    @Test
    fun `presence and absence are distinguishable`() {
        val entries = Tlv8.decode(Tlv8.Builder().separator().build())
        assertTrue(Tlv8.contains(entries, PairingComponent.SEPARATOR))
        assertFalse(Tlv8.contains(entries, PairingComponent.PROOF))
        assertEquals(0, Tlv8.value(entries, PairingComponent.SEPARATOR).size)
        assertEquals(0, Tlv8.value(entries, PairingComponent.PROOF).size)
    }

    @Test
    fun `single byte components read back`() {
        val entries = Tlv8.decode(Tlv8.Builder().add(PairingComponent.STATE, 4).build())
        assertEquals(4, Tlv8.byte(entries, PairingComponent.STATE))
        assertNull(Tlv8.byte(entries, PairingComponent.METHOD))
    }

    @Test
    fun `every component code is unique`() {
        val codes = PairingComponent.entries.map { it.code }
        assertEquals(codes.size, codes.toSet().size)
    }
}
