package dev.sidejit.coredevice

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The check-in a lockdown style service expects when it is reached through RSD.
 *
 * Services the RSD handshake marks as `UsesRemoteXPC` speak XPC over HTTP/2 and need none of
 * this. Everything else - dtservicehub and debugproxy among them - is an old lockdown service
 * that iOS exposes on its own tunnel port, and it stays silent until the client sends a
 * `RSDCheckin` property list. The device answers with its own `RSDCheckin` and then a
 * `StartService` message; only after those does the real protocol begin.
 *
 * Both replies are read as whole length prefixed messages and searched for the request name.
 * The reply may be XML or a binary property list and we only need to know which of the two
 * fixed answers arrived, so the names are matched in the raw bytes rather than by decoding a
 * property list this project has no reader for. A reply that carries neither name is reported
 * instead of being passed on to the service protocol, because leftover bytes would desynchronise
 * everything that follows.
 */
object RsdCheckin {
    class CheckinException(message: String) : Exception(message)

    private const val LABEL = "SideJITServer-Android"
    private const val MAX_MESSAGE = 1 shl 20

    fun perform(input: InputStream, output: OutputStream, serviceName: String) {
        writeMessage(output, requestPlist())
        TunnelDiagnostics.record("RSD check-in sent for $serviceName")

        val acknowledgement = readMessage(input, serviceName)
        if (!contains(acknowledgement, "RSDCheckin")) {
            throw CheckinException(
                "$serviceName did not acknowledge the RSD check-in: " + describe(acknowledgement),
            )
        }
        val start = readMessage(input, serviceName)
        if (!contains(start, "StartService")) {
            throw CheckinException(
                "$serviceName did not start after the RSD check-in: " + describe(start),
            )
        }
        TunnelDiagnostics.record("RSD check-in accepted by $serviceName")
    }

    private fun requestPlist(): ByteArray =
        (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
                "<plist version=\"1.0\"><dict>" +
                "<key>Label</key><string>" + LABEL + "</string>" +
                "<key>ProtocolVersion</key><string>2</string>" +
                "<key>Request</key><string>RSDCheckin</string>" +
                "</dict></plist>\n"
            ).toByteArray(Charsets.UTF_8)

    private fun writeMessage(output: OutputStream, body: ByteArray) {
        val framed = ByteBuffer.allocate(4 + body.size).order(ByteOrder.BIG_ENDIAN)
            .putInt(body.size).put(body).array()
        output.write(framed)
        output.flush()
    }

    private fun readMessage(input: InputStream, serviceName: String): ByteArray {
        val header = readExactly(input, 4, serviceName)
        val length = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).int
        if (length !in 1..MAX_MESSAGE) {
            throw CheckinException("$serviceName replied with an implausible length of $length bytes")
        }
        return readExactly(input, length, serviceName)
    }

    private fun readExactly(input: InputStream, count: Int, serviceName: String): ByteArray {
        val out = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = try {
                input.read(out, offset, count - offset)
            } catch (failure: Exception) {
                throw CheckinException(
                    "$serviceName stopped responding during the RSD check-in: " + failure.message,
                )
            }
            if (read < 0) throw EOFException("$serviceName closed the connection during the RSD check-in")
            offset += read
        }
        return out
    }

    private fun contains(haystack: ByteArray, needle: String): Boolean {
        val bytes = needle.toByteArray(Charsets.US_ASCII)
        if (bytes.size > haystack.size) return false
        outer@ for (start in 0..haystack.size - bytes.size) {
            for (index in bytes.indices) {
                if (haystack[start + index] != bytes[index]) continue@outer
            }
            return true
        }
        return false
    }

    private fun describe(message: ByteArray): String {
        val text = String(message, Charsets.UTF_8).filter { it.code in 32..126 }
        return if (text.length > 160) text.take(160) + "..." else text
    }
}
