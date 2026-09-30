package dev.sidejit.developer

import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset

/**
 * Minimal GDB remote serial protocol used by Apple's debugproxy path.
 *
 * SideJITServer enables JIT by launching the target suspended via DVT ProcessControl,
 * attaching with debugproxy (this protocol), then detaching so the kernel grants
 * get-task-allow JIT. Only the packets required for that sequence are implemented.
 *
 * Packet form: `$` + body + `#` + two hex checksum digits.
 * This layer is pure codec + attach/detach helpers. It does not open sockets itself.
 */
object GdbRemote {
    private val ASCII: Charset = Charsets.US_ASCII

    fun checksum(body: String): Int {
        var sum = 0
        for (ch in body) sum = (sum + ch.code) and 0xFF
        return sum
    }

    fun encode(body: String): String {
        val cs = checksum(body)
        return "$" + body + "#" + "%02x".format(cs)
    }

    fun decode(packet: String): String {
        require(packet.startsWith("$") && "#" in packet) {
            "not a GDB packet: ${packet.take(32)}"
        }
        val hash = packet.lastIndexOf('#')
        val body = packet.substring(1, hash)
        val given = packet.substring(hash + 1)
        val expected = "%02x".format(checksum(body))
        require(given.equals(expected, ignoreCase = true)) {
            "checksum mismatch: got $given expected $expected for body length ${body.length}"
        }
        return body
    }

    fun ack(): String = "+"
    fun nack(): String = "-"

    /** QStartNoAckMode — after this, no more +/- ACKs. */
    fun packetStartNoAck(): String = encode("QStartNoAckMode")

    fun packetSetDetachOnError(): String = encode("QSetDetachOnError:1")

    /** Attach to process id (decimal). */
    fun packetAttach(pid: Long): String = encode("vAttach;${pid.toString(16)}")

    /** Detach. */
    fun packetDetach(): String = encode("D")

    /** Continue. */
    fun packetContinue(): String = encode("c")

    /**
     * The SideJIT attach sequence once a debugproxy channel is open:
     * QStartNoAckMode, QSetDetachOnError, vAttach, D.
     * Returns the list of encoded packets to send in order.
     */
    fun jitAttachSequence(pid: Long): List<String> = listOf(
        packetStartNoAck(),
        packetSetDetachOnError(),
        packetAttach(pid),
        packetDetach(),
    )

    /**
     * Read one full `$...#XX` packet from [input], tolerating leading ACK bytes.
     */
    fun readPacket(input: InputStream): String {
        val buf = StringBuilder()
        var state = 0 // 0 wait $, 1 body, 2 checksum digit 1, 3 digit 2
        while (true) {
            val b = input.read()
            if (b < 0) throw java.io.EOFException("EOF while reading GDB packet")
            val ch = b.toChar()
            when (state) {
                0 -> if (ch == '$') {
                    buf.append(ch)
                    state = 1
                }
                1 -> {
                    buf.append(ch)
                    if (ch == '#') state = 2
                }
                2 -> {
                    buf.append(ch)
                    state = 3
                }
                3 -> {
                    buf.append(ch)
                    return buf.toString()
                }
            }
        }
    }

    fun writePacket(output: OutputStream, packet: String) {
        output.write(packet.toByteArray(ASCII))
        output.flush()
    }
}
