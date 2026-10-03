package dev.sidejit.pairing

import dev.sidejit.core.crypto.ChaChaPoly
import dev.sidejit.core.crypto.Digest
import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.Hkdf
import dev.sidejit.core.crypto.X25519
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.Tlv8
import dev.sidejit.core.serialization.jsonObject
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Exercises the initiator half of remote pairing against a stand-in that plays the device side.
 *
 * Passing means our two implementations agree about the role flip, the nonces and the signed
 * transcript. It does not prove an iPhone agrees; that needs hardware.
 */
class RemotePairingClientTest {

    private val identity = HostIdentity.generate(name = "SideJIT on a test machine")

    /** The device half: Ed25519 long term key plus whatever the host stored about it. */
    private class FakeDevice(val name: String = "Test iPhone") {
        val signingKey = Ed25519.generate()
        val identifier: String = UUID.randomUUID().toString().uppercase()
        val altIrk: ByteArray = ByteArray(16) { (it + 3).toByte() }

        fun record(): PairingRecord = PairingRecord(
            peer = PeerDevice(
                accountId = identifier,
                alternateIdentityKey = altIrk,
                model = "iPhone17,1",
                name = name,
                udid = UUID.randomUUID().toString().uppercase(),
                identifier = identifier,
                longTermPublicKey = signingKey.publicKey,
            ),
            sessionKey = ByteArray(64) { it.toByte() },
            establishedAtEpochSeconds = 1_700_000_000,
        )
    }

    private fun sessionKeyFor(sharedSecret: ByteArray): ByteArray = Hkdf.derive(
        Digest.SHA512,
        "Pair-Verify-Encrypt-Salt".toByteArray(Charsets.UTF_8),
        sharedSecret,
        "Pair-Verify-Encrypt-Info".toByteArray(Charsets.UTF_8),
        32,
    )

    /**
     * Runs [deviceSide] on a second thread with its own end of a bidirectional pipe and gives
     * [hostSide] the host end.
     */
    private fun <T> withPair(
        deviceSide: (RpPairingStream) -> Unit,
        hostSide: (RpPairingStream) -> T,
    ): T {
        val hostToDevice = PipedOutputStream()
        val deviceIn = PipedInputStream(hostToDevice, 1 shl 16)
        val deviceToHost = PipedOutputStream()
        val hostIn = PipedInputStream(deviceToHost, 1 shl 16)
        val device = RpPairingStream(deviceIn, deviceToHost, RpPairingStream.RESPONDER_ROLE)
        val host = RpPairingStream(hostIn, hostToDevice, RpPairingStream.INITIATOR_ROLE)
        val deviceFailure = AtomicReference<Throwable?>(null)
        val thread = Thread({
            try {
                deviceSide(device)
            } catch (failure: Throwable) {
                deviceFailure.set(failure)
            }
        }, "fake-device").apply { isDaemon = true; start() }
        try {
            return hostSide(host)
        } finally {
            thread.join(10_000)
            deviceFailure.get()?.let { throw AssertionError("the device side failed", it) }
        }
    }

    private fun deviceHandshake(stream: RpPairingStream, device: FakeDevice): Boolean {
        val request = stream.receivePlain()
        val attempt = request.path("request", "_0", "handshake", "_0", "hostOptions", "attemptPairVerify")
            ?.asBool == true
        stream.sendPlain(
            jsonObject(
                "response" to jsonObject(
                    "forRequestIdentifier" to JsonValue.of(0),
                    "_1" to jsonObject(
                        "handshake" to jsonObject(
                            "_0" to jsonObject(
                                "wireProtocolVersion" to JsonValue.of(26),
                                "deviceOptions" to jsonObject(
                                    "allowsIncomingTunnelConnections" to JsonValue.of(true),
                                ),
                                "peerDeviceInfo" to jsonObject(
                                    "udid" to JsonValue.of(device.identifier),
                                    "identifier" to JsonValue.of(device.identifier),
                                    "name" to JsonValue.of(device.name),
                                    "model" to JsonValue.of("iPhone17,1"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
        return attempt
    }

    private fun sendTlv(stream: RpPairingStream, payload: ByteArray) {
        stream.sendPlain(
            jsonObject(
                "event" to jsonObject(
                    "_0" to jsonObject(
                        "pairingData" to jsonObject(
                            "_0" to jsonObject(
                                "data" to JsonValue.of(Base64.getEncoder().encodeToString(payload)),
                                "startNewSession" to JsonValue.of(false),
                                "kind" to JsonValue.of("verifyManualPairing"),
                            ),
                        ),
                    ),
                ),
            ),
        )
    }

    private fun receiveTlv(stream: RpPairingStream): List<Tlv8.Entry> {
        val message = stream.receivePlain()
        val encoded = requireNotNull(message.path("event", "_0", "pairingData", "_0", "data")?.asText) {
            "the host sent no pairing data"
        }
        return Tlv8.decode(Base64.getDecoder().decode(encoded))
    }

    /**
     * Plays the device half of pair verify. Returns the shared secret it computed so the test
     * can check both sides agreed.
     */
    private fun deviceVerify(stream: RpPairingStream, device: FakeDevice): ByteArray {
        val m1 = receiveTlv(stream)
        assertEquals(1, Tlv8.byte(m1, PairingComponent.STATE))
        val hostPublic = Tlv8.value(m1, PairingComponent.PUBLIC_KEY)
        assertEquals(X25519.KEY_BYTES, hostPublic.size)

        val ephemeral = X25519.generate()
        val sharedSecret = ephemeral.agree(hostPublic)
        val sessionKey = sessionKeyFor(sharedSecret)
        val deviceInfo =
            ephemeral.publicKey + device.identifier.toByteArray(Charsets.UTF_8) + hostPublic
        val sealed = ChaChaPoly.seal(
            sessionKey,
            ChaChaPoly.nonce("PV-Msg02"),
            Tlv8.Builder()
                .add(PairingComponent.IDENTIFIER, device.identifier)
                .add(PairingComponent.SIGNATURE, device.signingKey.sign(deviceInfo))
                .build(),
        )
        sendTlv(
            stream,
            Tlv8.Builder()
                .add(PairingComponent.STATE, 2)
                .add(PairingComponent.PUBLIC_KEY, ephemeral.publicKey)
                .add(PairingComponent.ENCRYPTED_DATA, sealed)
                .build(),
        )

        val m3 = receiveTlv(stream)
        assertEquals(3, Tlv8.byte(m3, PairingComponent.STATE))
        val plain = ChaChaPoly.open(
            sessionKey,
            ChaChaPoly.nonce("PV-Msg03"),
            Tlv8.value(m3, PairingComponent.ENCRYPTED_DATA),
        )
        val hostTlv = Tlv8.decode(plain)
        val hostIdentifier = String(Tlv8.value(hostTlv, PairingComponent.IDENTIFIER), Charsets.UTF_8)
        val hostInfo = hostPublic + hostIdentifier.toByteArray(Charsets.UTF_8) + ephemeral.publicKey
        assertTrue(
            "the host signature should verify under the identity it claims",
            Ed25519.verify(
                hostPublicKeyFor(hostIdentifier),
                hostInfo,
                Tlv8.value(hostTlv, PairingComponent.SIGNATURE),
            ),
        )
        sendTlv(stream, Tlv8.Builder().add(PairingComponent.STATE, 4).build())
        return sharedSecret
    }

    private fun hostPublicKeyFor(identifier: String): ByteArray {
        assertEquals(identity.identifier, identifier)
        return identity.longTermPublicKey
    }

    @Test
    fun `verifies an existing pairing as the initiator`() {
        val device = FakeDevice()
        val record = device.record()
        val deviceSecret = AtomicReference<ByteArray?>(null)
        val session = withPair(
            deviceSide = { stream ->
                assertTrue("the host should ask to verify", deviceHandshake(stream, device))
                deviceSecret.set(deviceVerify(stream, device))
            },
            hostSide = { stream ->
                val client = RemotePairingClient(identity, stream)
                val handshake = client.handshake()
                assertEquals(26L, handshake.wireProtocolVersion)
                assertEquals(device.name, handshake.name)
                assertTrue(handshake.allowsIncomingTunnelConnections)
                client.verify(record)
            },
        )
        assertEquals(record, session.record)
        val secret = requireNotNull(deviceSecret.get()) { "the device never finished verify" }
        assertTrue("both sides must agree on the shared secret", secret.contentEquals(session.sharedSecret))
        assertEquals(SessionKeys.fromSharedSecret(secret), session.keys)
    }

    @Test
    fun `rejects a device that signs with the wrong key`() {
        val device = FakeDevice()
        val stored = device.record()
        // Store a record for a different long term key, as if the device had been re-paired
        // elsewhere. The signature must then fail to verify.
        val impostor = stored.copy(peer = stored.peer.copy(longTermPublicKey = Ed25519.generate().publicKey))
        var failure: Exception? = null
        withPair(
            deviceSide = { stream ->
                deviceHandshake(stream, device)
                runCatching { deviceVerify(stream, device) }
            },
            hostSide = { stream ->
                val client = RemotePairingClient(identity, stream)
                client.handshake()
                failure = runCatching { client.verify(impostor) }.exceptionOrNull() as? Exception
            },
        )
        assertTrue(
            "expected a signature failure, got $failure",
            failure is RpProtocolException && failure!!.message!!.contains("signature"),
        )
    }

    @Test
    fun `createListener uses the verified session and returns the port`() {
        val device = FakeDevice()
        val record = device.record()
        val port = withPair(
            deviceSide = { stream ->
                deviceHandshake(stream, device)
                val secret = deviceVerify(stream, device)
                val keys = SessionKeys.fromSharedSecret(secret)
                // The device reads with the host's write key and replies under the same nonce.
                val request = JsonValue.parse(
                    String(
                        ChaChaPoly.open(
                            keys.writeKey,
                            ChaChaPoly.rppairingNonce(0L),
                            (stream.receive() as RpMessage.Encrypted).ciphertext,
                        ),
                        Charsets.UTF_8,
                    ),
                )
                assertEquals(
                    Base64.getEncoder().encodeToString(secret),
                    request.path("request", "_0", "createListener", "key")?.asText,
                )
                assertEquals(
                    "tcp",
                    request.path("request", "_0", "createListener", "transportProtocolType")?.asText,
                )
                stream.sendEncrypted(
                    ChaChaPoly.seal(
                        keys.readKey,
                        ChaChaPoly.rppairingNonce(0L),
                        jsonObject(
                            "response" to jsonObject(
                                "_1" to jsonObject(
                                    "createListener" to jsonObject(
                                        "port" to JsonValue.of(49_152L),
                                        "devicePublicKey" to JsonValue.of("ignored"),
                                    ),
                                ),
                            ),
                        ).encode().toByteArray(Charsets.UTF_8),
                    ),
                )
            },
            hostSide = { stream ->
                val client = RemotePairingClient(identity, stream)
                client.handshake()
                val session = client.verify(record)
                RemotePairingControl.Channel(stream, session).createListener()
            },
        )
        assertEquals(49_152, port)
    }
}
