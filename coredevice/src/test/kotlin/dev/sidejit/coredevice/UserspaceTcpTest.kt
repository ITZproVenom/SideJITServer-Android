package dev.sidejit.coredevice

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UserspaceTcpTest {
    @Test fun parseIpv6() {
        val bytes = UserspaceTcp.parseIpv6("fd12:3456:789a:1::1")
        assertEquals(16, bytes.size)
        assertEquals(0xfd.toByte(), bytes[0])
    }

    @Test fun lengthPrefixedIpv6RoundTripWithTcp() {
        val local = ByteArray(16) { if (it == 15) 1 else 0 }
        val remote = ByteArray(16) { if (it == 15) 2 else 0 }
        val tcp = ByteArray(20); tcp[12] = 0x50.toByte(); tcp[13] = 0x02.toByte()
        val packet = ByteArray(60)
        packet[0] = 0x60.toByte(); packet[5] = 20; packet[6] = 6; packet[7] = 64
        System.arraycopy(local, 0, packet, 8, 16)
        System.arraycopy(remote, 0, packet, 24, 16)
        System.arraycopy(tcp, 0, packet, 40, 20)
        val out = ByteArrayOutputStream()
        TunnelDataPlane.writeLengthPrefixed(out, packet)
        val back = TunnelDataPlane.readLengthPrefixed(ByteArrayInputStream(out.toByteArray()))
        assertArrayEquals(packet, back)
        assertTrue(TunnelDataPlane.isIpv6(back))
    }

    @Test fun handshakeLoopback() {
        val c2s = PipedOutputStream()
        val sFromC = PipedInputStream(c2s, 65536)
        val s2c = PipedOutputStream()
        val cFromS = PipedInputStream(s2c, 65536)
        val params = TunnelParameters("fd00::1", "fd00::2", "ffff:ffff:ffff:ffff::", 1280, 58783)
        val exec = Executors.newSingleThreadExecutor()
        val fut = exec.submit {
            val syn = TunnelDataPlane.readPacket(sFromC)
            assertTrue(TunnelDataPlane.isIpv6(syn))
            val tcpOff = 40
            val clientSeq = ((syn[tcpOff+4].toInt() and 0xFF) shl 24) or ((syn[tcpOff+5].toInt() and 0xFF) shl 16) or ((syn[tcpOff+6].toInt() and 0xFF) shl 8) or (syn[tcpOff+7].toInt() and 0xFF)
            val clientPort = ((syn[tcpOff].toInt() and 0xFF) shl 8) or (syn[tcpOff+1].toInt() and 0xFF)
            val serverPort = ((syn[tcpOff+2].toInt() and 0xFF) shl 8) or (syn[tcpOff+3].toInt() and 0xFF)
            val reply = ByteArray(60)
            reply[0] = 0x60.toByte(); reply[5] = 20; reply[6] = 6; reply[7] = 64
            System.arraycopy(syn, 24, reply, 8, 16); System.arraycopy(syn, 8, reply, 24, 16)
            reply[tcpOff] = ((serverPort ushr 8) and 0xFF).toByte(); reply[tcpOff+1] = (serverPort and 0xFF).toByte()
            reply[tcpOff+2] = ((clientPort ushr 8) and 0xFF).toByte(); reply[tcpOff+3] = (clientPort and 0xFF).toByte()
            reply[tcpOff+6] = 0x03.toByte(); reply[tcpOff+7] = 0xe8.toByte()
            val ack = clientSeq + 1
            reply[tcpOff+8] = ((ack ushr 24) and 0xFF).toByte(); reply[tcpOff+9] = ((ack ushr 16) and 0xFF).toByte()
            reply[tcpOff+10] = ((ack ushr 8) and 0xFF).toByte(); reply[tcpOff+11] = (ack and 0xFF).toByte()
            reply[tcpOff+12] = 0x50.toByte(); reply[tcpOff+13] = 0x12.toByte()
            reply[tcpOff+14] = 0xff.toByte(); reply[tcpOff+15] = 0xff.toByte()
            TunnelDataPlane.writePacket(s2c, reply)
            TunnelDataPlane.readPacket(sFromC)
        }
        val stream = UserspaceTcp.connect(cFromS, c2s, params, 58783, 40000, 5000)
        fut.get(5, TimeUnit.SECONDS)
        stream.close(); exec.shutdownNow()
    }

    @Test fun tcpChecksumNonZero() {
        val src = ByteArray(16) { 0x11 }; val dst = ByteArray(16) { 0x22 }
        val hdr = ByteArray(20); hdr[12] = 0x50.toByte(); hdr[13] = 0x02.toByte()
        val csum = UserspaceTcp.tcpChecksum(src, dst, hdr, ByteArray(0))
        assertTrue(csum in 0..0xFFFF && csum != 0)
    }
}
