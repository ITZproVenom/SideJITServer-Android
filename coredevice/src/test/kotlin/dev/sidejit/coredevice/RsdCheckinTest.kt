package dev.sidejit.coredevice

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RsdCheckinTest {
    private fun framed(vararg bodies: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (body in bodies) {
            val bytes = body.toByteArray(Charsets.UTF_8)
            out.write(
                ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(bytes.size).array(),
            )
            out.write(bytes)
        }
        return out.toByteArray()
    }

    private fun plist(request: String): String =
        "<plist version=\"1.0\"><dict><key>Request</key><string>$request</string></dict></plist>"

    @Test
    fun `the check-in is length prefixed and names the request`() {
        val output = ByteArrayOutputStream()
        RsdCheckin.perform(
            ByteArrayInputStream(framed(plist("RSDCheckin"), plist("StartService"))),
            output,
            "com.apple.instruments.dtservicehub",
        )
        val sent = output.toByteArray()
        val declared = ByteBuffer.wrap(sent, 0, 4).order(ByteOrder.BIG_ENDIAN).int
        assertEquals(sent.size - 4, declared)
        val body = String(sent, 4, declared, Charsets.UTF_8)
        assertTrue(body.contains("<key>Request</key><string>RSDCheckin</string>"))
        assertTrue(body.contains("ProtocolVersion"))
    }

    private fun capture(reply: ByteArray): String =
        try {
            RsdCheckin.perform(
                ByteArrayInputStream(reply),
                ByteArrayOutputStream(),
                "com.apple.internal.dt.remote.debugproxy",
            )
            "the check-in was accepted"
        } catch (failure: RsdCheckin.CheckinException) {
            failure.message ?: ""
        }

    @Test
    fun `a service that does not acknowledge is reported`() {
        val failure = capture(framed(plist("Goodbye")))
        assertTrue(failure.contains("did not acknowledge"))
    }

    @Test
    fun `a service that acknowledges but never starts is reported`() {
        val failure = capture(framed(plist("RSDCheckin"), plist("Nope")))
        assertTrue(failure.contains("did not start"))
    }
}
