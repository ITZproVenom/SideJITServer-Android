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
        listener.onPaired = { paired.countDown() }
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

            // Start pair setup far enough to learn the code, then finish with it.
            probe.beginPairSetup()
            val code = awaitCode()
            assertEquals(6, code.length)
            probe.completePairSetup(code)

            assertTrue(paired.await(20, TimeUnit.SECONDS))
            val record = store.all().single()
            assertEquals(probe.identifier, record.peer.identifier)
            assertEquals(probe.name, record.peer.name)
            assertEquals(probe.model, record.peer.model)
            assertEquals(probe.udid, record.peer.udid)
            assertTrue(record.sessionKey.contentEquals(probe.sessionKey))
            assertEquals(64, record.sessionKey.size)
            assertTrue("the host signature should verify", probe.accessorySignatureValid)
            assertEquals(identity.identifier, probe.accessoryIdentifier)
            assertTrue(identity.longTermPublicKey.contentEquals(probe.accessoryPublicKey!!))
            assertTrue(failures.isEmpty())
        }
        assertTrue(finished.await(5, TimeUnit.SECONDS))
    }

    @Test
    fun `a wrong code is answered with an authentication error and nothing is stored`() {
        val (socket, stream) = connect()
        socket.use {
            val probe = TestDevice(stream, setupCode = "000000")
            probe.handshake()
            probe.beginPairSetup()
            awaitCode()
            probe.completePairSetupWithWrongProof()
            val response = probe.receiveTlv()
            assertEquals(4, Tlv8.byte(response, PairingComponent.STATE))
            assertEquals(0x02, Tlv8.byte(response, PairingComponent.ERROR))
        }
        assertTrue(finished.await(20, TimeUnit.SECONDS))
        assertTrue(store.all().isEmpty())
        assertFalse(failures.isEmpty())
    }

    @Test
    fun `a device asking to verify an existing pairing is refused`() {
        val (socket, stream) = connect()
        socket.use {
            val probe = TestDevice(stream, setupCode = "000000")
            var threw = false
            try {
                probe.handshake(attemptPairVerify = true)
            } catch (failure: Exception) {
                // The host closes the connection instead of answering.
                threw = true
            }
            assertTrue("the host should not answer a pair verify attempt", threw)
        }
        assertTrue(finished.await(20, TimeUnit.SECONDS))
        assertTrue(store.all().isEmpty())
        assertNotNull(failures.firstOrNull())
    }

    @Test
    fun `a pinless host uses the all zero code`() {
        listener.stop()
        val pinlessCodes = ArrayList<String>()
        val pinlessStore = InMemoryPairingStore()
        val pinlessListener = PairableHostListener(identity, pinlessStore, pinless = true)
        pinlessListener.onSetupCode = { code -> if (code != null) synchronized(pinlessCodes) { pinlessCodes.add(code) } }
        pinlessListener.start()
        try {
            val socket = Socket(InetAddress.getLoopbackAddress(), pinlessListener.port)
            socket.soTimeout = 20_000
            socket.use {
                val stream = RpPairingStream(
                    BufferedInputStream(socket.getInputStream()),
                    BufferedOutputStream(socket.getOutputStream()),
                    RpPairingStream.INITIATOR_ROLE,
                )
                val probe = TestDevice(stream, setupCode = "000000")
                val response = probe.handshake()
                assertEquals(
                    true,
                    response.path("response", "_1", "handshake", "_0", "deviceOptions", "allowsPinlessPairing")
                        ?.asBool,
                )
                probe.beginPairSetup()
                val deadline = System.currentTimeMillis() + 20_000
                var code: String? = null
                while (code == null && System.currentTimeMillis() < deadline) {
                    code = synchronized(pinlessCodes) { pinlessCodes.firstOrNull() }
                    if (code == null) Thread.sleep(10)
                }
                assertEquals("000000", code)
                probe.completePairSetup("000000")
                val deadline2 = System.currentTimeMillis() + 20_000
                while (pinlessStore.all().isEmpty() && System.currentTimeMillis() < deadline2) {
                    Thread.sleep(10)
                }
                assertEquals(1, pinlessStore.all().size)
            }
        } finally {
            pinlessListener.stop()
        }
    }
}