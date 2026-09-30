package dev.sidejit.coredevice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XpcTest {
    private val sample = XpcValue.Dict(
        linkedMapOf(
            "MessagingProtocolVersion" to XpcValue.UInt64(3),
            "Services" to XpcValue.Dict(linkedMapOf("com.apple.foo" to XpcValue.Dict(linkedMapOf("Port" to XpcValue.Text("49152"))))),
            "flag" to XpcValue.Bool(true),
            "neg" to XpcValue.Int64(-5),
            "pi" to XpcValue.Real(3.25),
            "blob" to XpcValue.Data(byteArrayOf(1, 2, 3)),
            "list" to XpcValue.Arr(listOf(XpcValue.Null, XpcValue.Text("ab"), XpcValue.Int64(9))),
            "odd" to XpcValue.Text("abc"),
        ),
    )

    @Test fun roundTrip() {
        val message = XpcMessage(XpcFlags.WANTING_REPLY, 42, sample)
        val decoded = Xpc.decode(Xpc.encode(message))
        assertEquals(42L, decoded.messageId)
        assertEquals(sample, decoded.body)
        assertTrue(decoded.flags and XpcFlags.DATA_PRESENT != 0)
        assertTrue(decoded.flags and XpcFlags.WANTING_REPLY != 0)
    }

    @Test fun emptyMessageHasNoBody() {
        val bytes = Xpc.encode(XpcMessage(0, 1, null))
        assertEquals(24, bytes.size)
        assertNull(Xpc.decode(bytes).body)
    }

    @Test fun wireLayoutOfAStringDictionary() {
        val bytes = Xpc.encode(XpcMessage(0, 0, XpcValue.Dict(linkedMapOf("a" to XpcValue.Text("b")))))
        val hex = bytes.joinToString("") { "%02x".format(it) }
        // wrapper magic 0x29b00b92 little endian
        assertTrue(hex.startsWith("920bb029"))
        // flags: ALWAYS_SET | DATA_PRESENT = 0x101
        assertEquals("01010000", hex.substring(8, 16))
        // body magic 0x42133742 then version 5
        assertEquals("4237134205000000", hex.substring(48, 64))
        // dict (0xf000), length 0x14, one entry, key "a\0\0\0", string (0x9000) length 2 "b\0" + 2 pad
        assertEquals("00f000001400000001000000" + "61000000" + "00900000" + "02000000" + "62000000", hex.substring(64))
    }

    @Test(expected = XpcException::class)
    fun badMagicIsRejected() { Xpc.decode(ByteArray(24)) }

    @Test(expected = XpcException::class)
    fun truncatedBodyIsRejected() {
        val bytes = Xpc.encode(XpcMessage(0, 1, sample))
        Xpc.decode(bytes.copyOf(bytes.size - 5))
    }
}
