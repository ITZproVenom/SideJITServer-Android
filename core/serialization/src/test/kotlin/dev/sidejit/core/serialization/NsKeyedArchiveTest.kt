package dev.sidejit.core.serialization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NsKeyedArchiveTest {
    @Test fun magicAndMinimumSize() {
        val bytes = NsKeyedArchive.encode(NsKeyedArchive.dict("k" to NsKeyedArchive.text("v")))
        assertTrue(bytes.size > 8)
        assertEquals("bplist00", String(bytes, 0, 8, Charsets.US_ASCII))
    }
    @Test fun methodInvocationProducesArchive() {
        val archive = NsKeyedArchive.methodInvocation(
            selector = "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:",
            namedArgs = mapOf(
                "bundleIdentifier" to NsKeyedArchive.text("com.example.app"),
                "options" to NsKeyedArchive.dict("StartSuspendedKey" to NsKeyedArchive.bool(true)),
            ),
        )
        assertTrue(archive.size > 40)
        assertEquals("bplist00", String(archive, 0, 8, Charsets.US_ASCII))
    }
    @Test fun emptyDict() { assertTrue(NsKeyedArchive.encode(NsKeyedArchive.dict()).size > 8) }
    @Test fun nestedArrayAndBool() {
        val bytes = NsKeyedArchive.encode(NsKeyedArchive.dict(
            "arr" to NsKeyedArchive.array(NsKeyedArchive.bool(true), NsKeyedArchive.integer(42), NsKeyedArchive.text("hi")),
        ))
        assertTrue(bytes.size > 20)
        assertEquals(0x62.toByte(), bytes[0])
    }
}
