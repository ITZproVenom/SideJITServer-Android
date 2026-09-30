package dev.sidejit.jit

import dev.sidejit.developer.GdbConnection
import dev.sidejit.developer.GdbProtocolException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.concurrent.thread

class JitOrchestratorTest {
    private class StubChannel(attachReply: String) : DebugChannel {
        private val toServer = PipedOutputStream()
        private val serverIn = PipedInputStream(toServer, 8192)
        private val toClient = PipedOutputStream()
        private val clientIn = PipedInputStream(toClient, 8192)
        override val input get() = clientIn
        override val output get() = toServer
        val attached = mutableListOf<String>()

        init {
            thread(isDaemon = true) {
                val conn = GdbConnection(serverIn, toClient)
                while (true) {
                    val cmd = try { conn.receive() } catch (_: Exception) { break }
                    attached += cmd
                    conn.send(if (cmd.startsWith("vAttach")) attachReply else "OK")
                    if (cmd == "QStartNoAckMode") conn.enterNoAckMode()
                    if (cmd == "D") break
                }
            }
        }
        override fun close() { runCatching { toServer.close() }; runCatching { toClient.close() } }
    }

    @Test fun grantsWhenAttachAndDetachSucceed() {
        val channel = StubChannel("T05")
        val result = JitOrchestrator({ 300 }, { channel }).enable("com.example.app")
        assertEquals(JitResult.Granted("com.example.app", 300), result)
        assertTrue(channel.attached.contains("vAttach;12c"))
    }

    @Test fun reportsTheStageWhenTheResolverFails() {
        val result = JitOrchestrator(UnavailableProcessResolver, UnavailableConnector).enable("com.example.app")
        result as JitResult.Failed
        assertEquals("DVT", result.stage)
    }

    @Test fun reportsTheStageWhenNoTunnelExists() {
        val result = JitOrchestrator({ 5 }, UnavailableConnector).enable("com.example.app")
        result as JitResult.Failed
        assertEquals("TUNNEL", result.stage)
    }

    @Test fun refusalFromDebugserverIsNeverReportedAsSuccess() {
        val result = JitOrchestrator({ 5 }, { StubChannel("E01") }).enable("com.example.app")
        result as JitResult.Failed
        assertEquals("GDB", result.stage)
    }

    @Test fun rejectsInvalidBundleIdentifiers() {
        val o = JitOrchestrator({ 5 }, { StubChannel("T05") })
        assertTrue(o.enable("") is JitResult.Failed)
        assertTrue(o.enable("has space") is JitResult.Failed)
    }
}

