package dev.sidejit.core.logging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class LogTest {

    @Before
    fun reset() {
        Log.clear()
        Log.minimumLevel = LogLevel.DEBUG
    }

    @Test
    fun `lines reach a sink and the ring`() {
        val seen = mutableListOf<LogLine>()
        val sink = LogSink { seen += it }
        Log.addSink(sink)
        try {
            Log.i(LogTag.MDNS, "advertising on 2 interfaces")
        } finally {
            Log.removeSink(sink)
        }
        assertEquals(1, seen.size)
        assertEquals(LogTag.MDNS, seen.single().tag)
        assertTrue(Log.recent().any { it.message.contains("advertising") })
    }

    @Test
    fun `secrets never reach the ring`() {
        Log.i(LogTag.PAIRING, "derived sharedKey=${"f".repeat(64)}")
        assertFalse(Log.recent().single().message.contains("f".repeat(64)))
    }

    @Test
    fun `level filtering drops quieter lines`() {
        Log.minimumLevel = LogLevel.WARN
        Log.d(LogTag.GDB, "packet")
        Log.w(LogTag.GDB, "retrying")
        assertEquals(listOf("retrying"), Log.recent().map { it.message })
    }

    @Test
    fun `describe walks the cause chain`() {
        val root = IllegalStateException("no route to host")
        val wrapper = RuntimeException("tunnel failed", root)
        val text = wrapper.describe()
        assertTrue(text.contains("tunnel failed"))
        assertTrue(text.contains("no route to host"))
    }
}
