package dev.sidejit.coredevice

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelDataPlaneTest {
    @Test
    fun lengthPrefixedRoundTrip() {
        val packet = ByteArray(60) { it.toByte() }
        val out = ByteArrayOutputStream()
        TunnelDataPlane.writeLengthPrefixed(out, packet)
        val back = TunnelDataPlane.readLengthPrefixed(ByteArrayInputStream(out.toByteArray()))
        assertTrue(back.contentEquals(packet))
    }

    @Test
    fun ipv6HeaderDetect() {
        val packet = ByteArray(40)
        packet[0] = 0x60.toByte()
        packet[4] = 0
        packet[5] = 0
        assertTrue(TunnelDataPlane.isIpv6(packet))
        val header = TunnelDataPlane.parseIpv6Header(packet)
        assertEquals(0, header.payloadLength)
    }
}
