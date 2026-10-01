package dev.sidejit.pairing

import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.Tlv8
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PairableHostTest {
    private val identity = HostIdentity.generate(name = "SideJIT on a test machine")
    private val store = InMemoryPairingStore()
    private lateinit var listener: PairableHostListener
    private val codes = ArrayList<String>()
    private val failures = ArrayList<String>()
    private val paired = CountDownLatch(1)
    private val finished = CountDownLatch(1)

    @Before
    fun start() {
        listener = PairableHostListener(identity, store, pinless = false)
        listener.onSetupCode = { code ->
            if (code != null) synchronized(codes) { codes.add(code) } else finished.countDown()
        }
        listener.onPaired = { _, _ -> paired.countDown() }
        listener.onFailure = { reason -> synchronized(failures) { failures.add(reason) } }
        listener.start()
    }

    @After
    fun stop() {
        listener.stop()
    }

    private fun connect(): Pair<Socket, RpPairingStream> {
        val socket = Socket(InetAddress.getLoopbackAddress(), listener.port)
        socket.soTimeout = 20_000
        return socket to RpPairingStream(
            BufferedInputStream(socket.getInputStream()),
            BufferedOutputStream(socket.getOutputStream()),
            RpPairingStream.INITIATOR_ROLE,
        )
    }

    private fun awaitCode(): String {
        val deadline = System.currentTimeMillis() + 20_000
        while (System.currentTimeMillis() < deadline) {
            synchronized(codes) { codes.firstOrNull() }?.let { return it }
            Thread.sleep(10)
        }
        throw AssertionError("no setup code was offered")
    }

    @Test
    fun `a device pairs end to end and both sides agree on the session key`() {
        val (socket, stream) = connect()
        socket.use {
            val probe = TestDevice(stream, setupCode = "000000")
            val response = probe.handshake()
            assertEquals(
                identity.identifier,
                response.path("response", "_1", "handshake", "_0", "peerDeviceInfo", "identifier")?.asText,
            )
            assertEquals(
                26L,
                response.path("response", "_1", "handshake", "_0", "wireProtocolVersion")?.asLong,
            )
            assertEquals(
                false,
                response.path("response", "_1", "handshake", "_0", "deviceOptions", "allowsPinlessPairing")
                    ?.asBool,
            )

            val published = awaitCode()
            probe.setupCode = published
            probe.completePairSetup()

            assertTrue("pair did not complete", paired.await(20, TimeUnit.SECONDS))
            assertTrue(failures.isEmpty())
            assertEquals(1, store.all().size)
        }
    }
}
