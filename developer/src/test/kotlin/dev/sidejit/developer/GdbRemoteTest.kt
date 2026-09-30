package dev.sidejit.developer

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.concurrent.thread

class GdbRemoteTest {
    @Test fun checksumOfOkIsNineA() {
        assertEquals("$" + "OK#9a", String(GdbPacket.encode("OK")))
    }

    @Test fun reservedBytesAreEscaped() {
        val encoded = GdbPacket.encode(byteArrayOf('a'.code.toByte(), '#'.code.toByte(), '}'.code.toByte()))
        val body = String(encoded).substring(1, String(encoded).indexOf('#', 1).let { if (it < 0) 0 else it })
        assertTrue(body.startsWith("a}\u0003"))
        val roundTrip = GdbPacket.unpack(GdbPacket.escape(byteArrayOf('a'.code.toByte(), '#'.code.toByte(), '}'.code.toByte(), '*'.code.toByte())))
        assertArrayEquals(byteArrayOf('a'.code.toByte(), '#'.code.toByte(), '}'.code.toByte(), '*'.code.toByte()), roundTrip)
    }

    @Test fun runLengthEncodingExpands() {
        // '0' then '*' with count char ' ' (0x20): 0x20 - 29 = 3 extra repeats
        assertEquals("0000", String(GdbPacket.unpack("0* ".toByteArray())))
    }

    @Test fun receiveAcknowledgesAndValidatesChecksum() {
        val out = ByteArrayOutputStream()
        val conn = GdbConnection(ByteArrayInputStream("+\$OK#9a".toByteArray()), out)
        assertEquals("OK", conn.receive())
        assertEquals("+", out.toString())
    }

    @Test(expected = GdbProtocolException::class)
    fun badChecksumIsRejected() {
        GdbConnection(ByteArrayInputStream("\$OK#00".toByteArray()), ByteArrayOutputStream()).receive()
    }

    @Test fun attachThenDetachAgainstAStubServer() {
        val toServer = PipedOutputStream(); val serverIn = PipedInputStream(toServer, 8192)
        val toClient = PipedOutputStream(); val clientIn = PipedInputStream(toClient, 8192)
        val seen = mutableListOf<String>()
        val server = thread {
            val conn = GdbConnection(serverIn, toClient)
            val replies = mapOf("QStartNoAckMode" to "OK", "QSetDetachOnError:1" to "OK", "vAttach;1f4" to "T05thread:1;", "D" to "OK")
            while (true) {
                val cmd = try { conn.receive() } catch (_: Exception) { break }
                seen += cmd
                conn.send(replies[cmd] ?: "E01")
                if (cmd == "QStartNoAckMode") conn.enterNoAckMode()
                if (cmd == "D") break
            }
        }
        val outcome = DebugAttach(GdbConnection(clientIn, toServer)).attachAndDetach(500)
        server.join(2000)
        assertEquals(500, outcome.pid)
        assertEquals(listOf("QStartNoAckMode", "QSetDetachOnError:1", "vAttach;1f4", "D"), seen)
        assertFalse(seen.contains("E01"))
    }

    @Test(expected = GdbProtocolException::class)
    fun failedAttachIsReported() {
        val toServer = PipedOutputStream(); val serverIn = PipedInputStream(toServer, 8192)
        val toClient = PipedOutputStream(); val clientIn = PipedInputStream(toClient, 8192)
        thread {
            val conn = GdbConnection(serverIn, toClient)
            while (true) {
                val cmd = try { conn.receive() } catch (_: Exception) { break }
                conn.send(if (cmd.startsWith("vAttach")) "E01" else "OK")
                if (cmd == "QStartNoAckMode") conn.enterNoAckMode()
            }
        }
        DebugAttach(GdbConnection(clientIn, toServer)).attachAndDetach(7)
    }
}
