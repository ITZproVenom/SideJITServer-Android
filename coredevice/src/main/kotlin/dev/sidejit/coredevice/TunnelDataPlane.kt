package dev.sidejit.coredevice

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * After CDTunnel handshake, the data plane carries raw IPv6 packets.
 * Some paths length-prefix with a 4-byte big-endian size; CoreDeviceProxy
 * over lockdown uses raw packet boundaries. This codec supports both modes.
 */
object TunnelDataPlane {
    fun writeLengthPrefixed(output: OutputStream, packet: ByteArray) {
        require(packet.isNotEmpty()) { "empty packet" }
        val header = ByteArray(4)
        header[0] = ((packet.size ushr 24) and 0xFF).toByte()
        header[1] = ((packet.size ushr 16) and 0xFF).toByte()
        header[2] = ((packet.size ushr 8) and 0xFF).toByte()
        header[3] = (packet.size and 0xFF).toByte()
        output.write(header)
        output.write(packet)
        output.flush()
    }

    fun readLengthPrefixed(input: InputStream): ByteArray {
        val header = readExactly(input, 4)
        val size = ((header[0].toInt() and 0xFF) shl 24) or
            ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or
            (header[3].toInt() and 0xFF)
        require(size in 1..65536) { "implausible packet size $size" }
        return readExactly(input, size)
    }

    fun isIpv6(packet: ByteArray): Boolean =
        packet.isNotEmpty() && ((packet[0].toInt() ushr 4) and 0xF) == 6

    /** Minimal IPv6 header parse: payload length and next header. */
    data class Ipv6Header(
        val payloadLength: Int,
        val nextHeader: Int,
        val hopLimit: Int,
        val source: ByteArray,
        val destination: ByteArray,
    )

    fun parseIpv6Header(packet: ByteArray): Ipv6Header {
        require(packet.size >= 40) { "IPv6 header needs 40 bytes" }
        require(isIpv6(packet)) { "not IPv6" }
        val payloadLength = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        return Ipv6Header(
            payloadLength = payloadLength,
            nextHeader = packet[6].toInt() and 0xFF,
            hopLimit = packet[7].toInt() and 0xFF,
            source = packet.copyOfRange(8, 24),
            destination = packet.copyOfRange(24, 40),
        )
    }

    private fun readExactly(input: InputStream, count: Int): ByteArray {
        val buf = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(buf, read, count - read)
            if (n < 0) throw EOFException("EOF after $read of $count")
            read += n
        }
        return buf
    }
}
