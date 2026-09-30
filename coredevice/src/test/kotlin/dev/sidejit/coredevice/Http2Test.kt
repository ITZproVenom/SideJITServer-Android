package dev.sidejit.coredevice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Http2Test {
    @Test
    fun frameRoundTrip() {
        val payload = "hello".toByteArray()
        val encoded = Http2.encodeFrame(Http2.FRAME_DATA, Http2.FLAG_END_STREAM, 1, payload)
        val frame = Http2.decodeFrame(encoded)
        assertEquals(Http2.FRAME_DATA, frame.type)
        assertEquals(1, frame.streamId)
        assertTrue(frame.payload.contentEquals(payload))
    }

    @Test
    fun clientPrefaceStartsWithPri() {
        val preface = String(Http2.CLIENT_PREFACE, Charsets.US_ASCII)
        assertTrue(preface.startsWith("PRI * HTTP/2.0"))
    }
}
