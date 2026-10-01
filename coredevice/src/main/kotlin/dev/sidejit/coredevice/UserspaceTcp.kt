package dev.sidejit.coredevice

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

/** Client-only TCP over length-prefixed IPv6 tunnel packets. No retransmit. */
object UserspaceTcp {
    class TcpException(message: String, cause: Throwable? = null) : IOException(message, cause)
    private const val PROTO_TCP = 6
    private const val TCP_HEADER_MIN = 20
    private const val IPV6_HEADER = 40
    private const val FLAG_FIN = 0x01
    private const val FLAG_SYN = 0x02
    private const val FLAG_RST = 0x04
    private const val FLAG_PSH = 0x08
    private const val FLAG_ACK = 0x10

    data class Endpoint(val address: ByteArray, val port: Int) {
        init { require(address.size == 16); require(port in 1..65535) }
        override fun equals(other: Any?) = other is Endpoint && other.port == port && other.address.contentEquals(address)
        override fun hashCode() = address.contentHashCode() * 31 + port
    }

    fun parseIpv6(text: String): ByteArray {
        val addr = InetAddress.getByName(text.trim()) as? Inet6Address
            ?: throw TcpException("not an IPv6 address: $text")
        return addr.address
    }

    fun connect(
        tunnelInput: InputStream, tunnelOutput: OutputStream, parameters: TunnelParameters,
        remotePort: Int = parameters.serverRsdPort, localPort: Int = 40000 + Random.nextInt(20000),
        timeoutMs: Long = 15_000,
    ): TcpStream {
        val local = Endpoint(parseIpv6(parameters.clientAddress), localPort)
        val remote = Endpoint(parseIpv6(parameters.serverAddress), remotePort)
        return TcpStream(tunnelInput, tunnelOutput, local, remote, timeoutMs).also { it.handshake() }
    }

    class TcpStream(
        private val tunnelIn: InputStream, private val tunnelOut: OutputStream,
        private val local: Endpoint, private val remote: Endpoint, private val timeoutMs: Long,
    ) : AutoCloseable {
        private val closed = AtomicBoolean(false)
        private var sendNext = 0
        private var recvNext = 0
        private val recvBuffer = ByteArrayOutputStream()
        private val lock = Any()

        val input: InputStream = object : InputStream() {
            override fun read(): Int {
                val b = ByteArray(1)
                val n = read(b, 0, 1)
                return if (n <= 0) -1 else b[0].toInt() and 0xFF
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len <= 0) return 0
                synchronized(lock) {
                    while (recvBuffer.size() == 0 && !closed.get()) {
                        pump(true)
                        if (recvBuffer.size() == 0 && closed.get()) return -1
                    }
                    val available = recvBuffer.toByteArray()
                    if (available.isEmpty()) return -1
                    val n = minOf(len, available.size)
                    System.arraycopy(available, 0, b, off, n)
                    recvBuffer.reset()
                    if (n < available.size) recvBuffer.write(available, n, available.size - n)
                    return n
                }
            }
            override fun available(): Int = synchronized(lock) { recvBuffer.size() }
        }

        val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()))
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len <= 0) return
                synchronized(lock) {
                    if (closed.get()) throw TcpException("stream closed")
                    sendData(b.copyOfRange(off, off + len))
                }
            }
            override fun flush() {}
        }

        fun handshake() {
            val isn = Random.nextInt() and 0x7FFFFFFF
            sendNext = isn
            sendSegment(FLAG_SYN, ByteArray(0), 0)
            sendNext = isn + 1
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val seg = receiveSegment(true) ?: continue
                if (seg.flags and FLAG_RST != 0) throw TcpException("RST during handshake")
                if (seg.flags and FLAG_SYN != 0 && seg.flags and FLAG_ACK != 0) {
                    if (seg.ack != sendNext) throw TcpException("SYN-ACK ack mismatch")
                    recvNext = seg.seq + 1
                    sendSegment(FLAG_ACK, ByteArray(0), recvNext)
                    return
                }
            }
            throw TcpException("SYN-ACK timeout after ${timeoutMs}ms")
        }

        private fun sendData(payload: ByteArray) {
            var offset = 0
            while (offset < payload.size) {
                val n = minOf(payload.size - offset, 1220)
                val chunk = payload.copyOfRange(offset, offset + n)
                sendSegment(FLAG_PSH or FLAG_ACK, chunk, recvNext)
                sendNext += chunk.size
                offset += n
            }
        }

        private fun sendSegment(flags: Int, payload: ByteArray, ack: Int) {
            val tcp = buildTcpHeader(local.port, remote.port, sendNext, ack, flags, 65535)
            val csum = tcpChecksum(local.address, remote.address, tcp, payload)
            tcp[16] = ((csum ushr 8) and 0xFF).toByte()
            tcp[17] = (csum and 0xFF).toByte()
            val packet = ByteArray(IPV6_HEADER + tcp.size + payload.size)
            packet[0] = 0x60.toByte()
            val plen = tcp.size + payload.size
            packet[4] = ((plen ushr 8) and 0xFF).toByte()
            packet[5] = (plen and 0xFF).toByte()
            packet[6] = PROTO_TCP.toByte()
            packet[7] = 64
            System.arraycopy(local.address, 0, packet, 8, 16)
            System.arraycopy(remote.address, 0, packet, 24, 16)
            System.arraycopy(tcp, 0, packet, IPV6_HEADER, tcp.size)
            System.arraycopy(payload, 0, packet, IPV6_HEADER + tcp.size, payload.size)
            TunnelDataPlane.writePacket(tunnelOut, packet)
        }

        private data class Segment(val seq: Int, val ack: Int, val flags: Int, val window: Int, val payload: ByteArray)

        private fun receiveSegment(allowBlock: Boolean): Segment? {
            while (true) {
                val packet = try {
                    if (!allowBlock && tunnelIn.available() == 0) return null
                    TunnelDataPlane.readPacket(tunnelIn)
                } catch (e: EOFException) {
                    closed.set(true)
                    return null
                } catch (e: Exception) {
                    if (!allowBlock) return null
                    throw TcpException("tunnel read failed: ${e.message}", e)
                }
                if (!TunnelDataPlane.isIpv6(packet) || packet.size < IPV6_HEADER + TCP_HEADER_MIN) continue
                val hdr = TunnelDataPlane.parseIpv6Header(packet)
                if (hdr.nextHeader != PROTO_TCP) continue
                if (!hdr.destination.contentEquals(local.address)) continue
                if (!hdr.source.contentEquals(remote.address)) continue
                val tcpOff = IPV6_HEADER
                val headerLen = ((packet[tcpOff + 12].toInt() ushr 4) and 0xF) * 4
                if (headerLen < TCP_HEADER_MIN || packet.size < tcpOff + headerLen) continue
                val srcPort = ((packet[tcpOff].toInt() and 0xFF) shl 8) or (packet[tcpOff + 1].toInt() and 0xFF)
                val dstPort = ((packet[tcpOff + 2].toInt() and 0xFF) shl 8) or (packet[tcpOff + 3].toInt() and 0xFF)
                if (srcPort != remote.port || dstPort != local.port) continue
                val seq = bytesToInt(packet, tcpOff + 4)
                val ack = bytesToInt(packet, tcpOff + 8)
                val flags = packet[tcpOff + 13].toInt() and 0xFF
                val window = ((packet[tcpOff + 14].toInt() and 0xFF) shl 8) or (packet[tcpOff + 15].toInt() and 0xFF)
                val payloadStart = tcpOff + headerLen
                val payload = if (payloadStart < packet.size) packet.copyOfRange(payloadStart, packet.size) else ByteArray(0)
                if (payload.isNotEmpty() && seq == recvNext) {
                    recvBuffer.write(payload)
                    recvNext += payload.size
                    sendSegment(FLAG_ACK, ByteArray(0), recvNext)
                } else if (payload.isNotEmpty() && seq < recvNext) {
                    sendSegment(FLAG_ACK, ByteArray(0), recvNext)
                }
                if (flags and FLAG_FIN != 0) {
                    recvNext = maxOf(recvNext, seq + 1)
                    sendSegment(FLAG_ACK, ByteArray(0), recvNext)
                    closed.set(true)
                }
                if (flags and FLAG_RST != 0) closed.set(true)
                return Segment(seq, ack, flags, window, payload)
            }
        }

        private fun pump(allowBlock: Boolean) { receiveSegment(allowBlock) }

        override fun close() {
            if (closed.compareAndSet(false, true)) {
                try {
                    synchronized(lock) {
                        sendSegment(FLAG_FIN or FLAG_ACK, ByteArray(0), recvNext)
                        sendNext += 1
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun buildTcpHeader(srcPort: Int, dstPort: Int, seq: Int, ack: Int, flags: Int, window: Int): ByteArray {
        val hdr = ByteArray(TCP_HEADER_MIN)
        hdr[0] = ((srcPort ushr 8) and 0xFF).toByte()
        hdr[1] = (srcPort and 0xFF).toByte()
        hdr[2] = ((dstPort ushr 8) and 0xFF).toByte()
        hdr[3] = (dstPort and 0xFF).toByte()
        putInt(hdr, 4, seq)
        putInt(hdr, 8, ack)
        hdr[12] = (5 shl 4).toByte()
        hdr[13] = flags.toByte()
        hdr[14] = ((window ushr 8) and 0xFF).toByte()
        hdr[15] = (window and 0xFF).toByte()
        return hdr
    }

    internal fun tcpChecksum(src: ByteArray, dst: ByteArray, tcpHeader: ByteArray, payload: ByteArray): Int {
        val len = tcpHeader.size + payload.size
        val sum = ByteArrayOutputStream()
        sum.write(src)
        sum.write(dst)
        sum.write(byteArrayOf(
            ((len ushr 24) and 0xFF).toByte(), ((len ushr 16) and 0xFF).toByte(),
            ((len ushr 8) and 0xFF).toByte(), (len and 0xFF).toByte(),
        ))
        sum.write(byteArrayOf(0, 0, 0, PROTO_TCP.toByte()))
        sum.write(tcpHeader)
        sum.write(payload)
        return onesComplement(sum.toByteArray())
    }

    private fun onesComplement(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < data.size) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < data.size) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun putInt(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value ushr 24) and 0xFF).toByte()
        buf[off + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[off + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[off + 3] = (value and 0xFF).toByte()
    }

    private fun bytesToInt(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)
}
