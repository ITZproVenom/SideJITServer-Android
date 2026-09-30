package dev.sidejit.developer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessControlTest {
    @Test fun launchArchiveIsBplist() {
        val archive = ProcessControl.launchSuspendedArchive("com.example.jit")
        assertTrue(archive.size > 40)
        assertEquals("bplist00", String(archive, 0, 8, Charsets.US_ASCII))
    }
    @Test fun launchJsonHasMethod() {
        val method = ProcessControl.launchSuspended("com.example.jit").path("method")?.asText
        assertTrue(method != null && method!!.contains("launchSuspended"))
    }
    @Test fun serviceName() {
        assertEquals("com.apple.instruments.server.services.processcontrol", ProcessControl.SERVICE)
    }
}
