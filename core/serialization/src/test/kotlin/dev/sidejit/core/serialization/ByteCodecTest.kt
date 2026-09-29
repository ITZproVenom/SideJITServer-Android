package dev.sidejit.core.serialization

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ByteCodecTest {

    @Test
    fun `big endian integers round trip`() {
        val bytes = ByteWriter()
            .u8(0xAB)
            .u16(0x1234)
            .u32(0xDEADBEEFL)
            .u64(0x0102030405060708L)
            .toByteArray()
        assertEquals(15, bytes.size)
        val reader = ByteReader(bytes)
        assertEquals(0xAB, reader.u8())
        assertEquals(0x1234, reader.u16())
        assertEquals(0xDEADBEEFL, reader.u32())
        assertEquals(0x0102030405060708L, reader.u64())
        assertFalse(reader.hasMore)
    }

    @Test
    fun `little endian integers round trip`() {
        val bytes = ByteWriter().u16le(0x1234).u32le(0xDEADBEEFL).u64le(-1L).toByteArray()
        val reader = ByteReader(bytes)
        assertEquals(0x1234, reader.u16le())
        assertEquals(0xDEADBEEFL, reader.u32le())
        assertEquals(-1L, reader.u64le())
    }

    @Test
    fun `endianness is not confused`() {
        assertArrayEquals(byteArrayOf(0x12, 0x34), ByteWriter().u16(0x1234).toByteArray())
        assertArrayEquals(byteArrayOf(0x34, 0x12), ByteWriter().u16le(0x1234).toByteArray())
    }

    @Test(expected = ByteReader.TruncatedException::class)
    fun `reading past the end is refused`() {
        ByteReader(byteArrayOf(1, 2, 3)).u32()
    }

    @Test(expected = ByteReader.TruncatedException::class)
    fun `an oversized length prefix is refused`() {
        val reader = ByteReader(byteArrayOf(0, 0, 0x10, 0))
        reader.bytes(reader.u16().let { 0x1000 })
    }

    @Test
    fun `peek does not consume`() {
        val reader = ByteReader(byteArrayOf(9, 8))
        assertEquals(9, reader.peekU8())
        assertEquals(9, reader.u8())
        assertEquals(8, reader.u8())
    }

    @Test
    fun `hex round trips both ways`() {
        val bytes = byteArrayOf(0x00, 0x0f, 0x7f, -1)
        assertEquals("000f7fff", bytes.toHex())
        assertArrayEquals(bytes, "000f7fff".hexToBytes())
        assertArrayEquals(bytes, "00:0f 7f ff".hexToBytes())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `odd hex is refused`() {
        "abc".hexToBytes()
    }

    @Test
    fun `constant time comparison still compares`() {
        assertTrue(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertFalse(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertFalse(constantTimeEquals(byteArrayOf(1, 2), byteArrayOf(1, 2, 3)))
    }

    @Test
    fun `concat joins in order`() {
        assertArrayEquals(
            byteArrayOf(1, 2, 3, 4, 5),
            byteArrayOf(1, 2).concat(byteArrayOf(3), byteArrayOf(4, 5))
        )
    }

    @Test
    fun `utf8 survives the trip`() {
        val bytes = ByteWriter().utf8("iPhone 17 Pro").toByteArray()
        assertEquals("iPhone 17 Pro", ByteReader(bytes).utf8(bytes.size))
    }
}
