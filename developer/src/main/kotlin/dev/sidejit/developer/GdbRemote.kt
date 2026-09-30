package dev.sidejit.developer

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/** Thrown when the debug server says something the GDB remote protocol does not allow. */
class GdbProtocolException(message: String) : Exception(message)

/**
 * GDB remote serial protocol packet framing: `$<data>#<checksum>`.
 *
 * Bytes `$ # } *` inside the data are escaped as `}` followed by the byte XOR
 * 0x20. Incoming data may also use run-length encoding (`*` followed by a
 * count character), which debugserver does use.
 */
object GdbPacket {
    fun checksum(escapedBody: ByteArray): Int {
        var sum = 0
        for (b in escapedBody) sum = (sum + (b.toInt() and 0xFF)) and 0xFF
        return sum
    }

    fun escape(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(data.size + 8)
        for (b in data) {
            val v = b.toInt() and 0xFF
            if (v == '$'.code || v == '#'.code || v == '}'.code || v == '*'.code) {
                out.write('}'.code)
                out.write(v xor 0x20)
            } else {
                out.write(v)
            }
        }
        return out.toByteArray()
    }

    fun encode(data: ByteArray): ByteArray {
        val body = escape(data)
        val out = ByteArrayOutputStream(body.size + 4)
        out.write('$'.code)
        out.write(body)
        out.write('#'.code)
        out.write("%02x".format(checksum(body)).toByteArray(Charsets.US_ASCII))
        return out.toByteArray()
    }

    fun encode(text: String): ByteArray = encode(text.toByteArray(Charsets.ISO_8859_1))

    /** Undo escaping and run-length encoding on a packet body. */
    fun unpack(body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(body.size)
        var i = 0
        var last = -1
        while (i < body.size) {
            val v = body[i].toInt() and 0xFF
            when {
                v == '}'.code -> {
                    if (i + 1 >= body.size) throw GdbProtocolException("dangling escape")
                    last = (body[i + 1].toInt() and 0xFF) xor 0x20
                    out.write(last)
                    i += 2
                }
                v == '*'.code -> {
                    if (last < 0 || i + 1 >= body.size) throw GdbProtocolException("bad run-length encoding")
                    val count = (body[i + 1].toInt() and 0xFF) - 29
                    if (count < 0) throw GdbProtocolException("bad run-length count")
                    repeat(count) { out.write(last) }
                    i += 2
                }
                else -> {
                    last = v
                    out.write(v)
                    i++
                }
            }
        }
        return out.toByteArray()
    }
}

/**
 * One GDB remote conversation over a byte stream (the debugserver socket
 * reached through the tunnel). Not thread safe; one command at a time.
 */
class GdbConnection(
    private val input: InputStream,
    private val output: OutputStream,
) {
    /** After `QStartNoAckMode` the `+`/`-` acknowledgements stop. */
    var ackMode: Boolean = true
        private set

    fun send(command: String) {
        val packet = GdbPacket.encode(command)
        Log.d(LogTag.GDB, "-> ${command.take(64)}")
        repeat(3) {
            output.write(packet)
            output.flush()
            if (!ackMode) return
            when (val ack = readByte()) {
                '+'.code -> return
                '-'.code -> Log.w(LogTag.GDB, "packet NAKed, resending")
                else -> throw GdbProtocolException("expected an acknowledgement, got byte $ack")
            }
        }
        throw GdbProtocolException("the debug server rejected the packet three times")
    }

    fun receive(): String {
        while (true) {
            val b = readByte()
            if (b == '$'.code) break
            // Stray '+' / '-' / notification bytes between packets are skipped.
        }
        val body = ByteArrayOutputStream()
        while (true) {
            val b = readByte()
            if (b == '#'.code) break
            body.write(b)
        }
        val checksumText = String(byteArrayOf(readByte().toByte(), readByte().toByte()), Charsets.US_ASCII)
        val expected = checksumText.toIntOrNull(16) ?: throw GdbProtocolException("bad checksum text")
        val raw = body.toByteArray()
        if (GdbPacket.checksum(raw) != expected) {
            if (ackMode) {
                output.write('-'.code)
                output.flush()
            }
            throw GdbProtocolException("checksum mismatch")
        }
        if (ackMode) {
            output.write('+'.code)
            output.flush()
        }
        val text = String(GdbPacket.unpack(raw), Charsets.ISO_8859_1)
        Log.d(LogTag.GDB, "<- ${text.take(64)}")
        return text
    }

    fun transact(command: String): String {
        send(command)
        return receive()
    }

    /** Ask the server to stop acknowledging packets. */
    fun startNoAckMode() {
        val reply = transact("QStartNoAckMode")
        if (reply != "OK") throw GdbProtocolException("QStartNoAckMode refused: $reply")
        ackMode = false
    }

    /** For a stub or proxy playing the server side, mirroring the client's switch. */
    fun enterNoAckMode() {
        ackMode = false
    }

    private fun readByte(): Int {
        val b = input.read()
        if (b < 0) throw GdbProtocolException("the debug server closed the connection")
        return b
    }
}

