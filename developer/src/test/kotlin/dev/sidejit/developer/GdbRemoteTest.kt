package dev.sidejit.developer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GdbRemoteTest {
    @Test
    fun checksum_QStartNoAckMode() {
        // Known vector used across SideJIT implementations: body sums to 0xb0
        assertEquals(0xb0, GdbRemote.checksum("QStartNoAckMode"))
        assertEquals("\$QStartNoAckMode#b0", GdbRemote.encode("QStartNoAckMode"))
    }

    @Test
    fun detach_packet() {
        assertEquals("\$D#44", GdbRemote.encode("D"))
    }

    @Test
    fun roundTrip() {
        val body = "vAttach;1a2b"
        val packet = GdbRemote.encode(body)
        assertEquals(body, GdbRemote.decode(packet))
    }

    @Test
    fun jitSequence_order() {
        val seq = GdbRemote.jitAttachSequence(0x1a2b)
        assertEquals(4, seq.size)
        assertTrue(seq[0].startsWith("\$QStartNoAckMode#"))
        assertTrue(seq[1].contains("QSetDetachOnError"))
        assertTrue(seq[2].contains("vAttach;1a2b"))
        assertEquals("\$D#44", seq[3])
    }
}
