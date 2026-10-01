package dev.sidejit.pairing

import dev.sidejit.core.crypto.ChaChaPoly
import dev.sidejit.core.crypto.Digest
import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.Hkdf
import dev.sidejit.core.crypto.X25519
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.PairingComponent
import dev.sidejit.core.serialization.PairingError
import dev.sidejit.core.serialization.Tlv8
import dev.sidejit.core.serialization.jsonObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64

object PairVerifyClient {
    data class Result(val session: VerifiedSession, val listenerPort: Int)

    fun connect(host: String, port: Int, identity: HostIdentity, record: PairingRecord, timeoutMs: Int = 15_000): Result {
        Log.i(LogTag.PAIRING, "connecting to device RPPairing endpoint $host:$port for pair-verify")
        val socket = Socket()
        socket.tcpNoDelay = true
        socket.soTimeout = timeoutMs
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        socket.use {
            val stream = RpPairingStream(
                BufferedInputStream(socket.getInputStream()),
                BufferedOutputStream(socket.getOutputStream()),
                RpPairingStream.INITIATOR_ROLE,
            )
            stream.sendPlain(jsonObject(
                "request" to jsonObject("_0" to jsonObject(
                    "handshake" to jsonObject("_0" to jsonObject(
                        "hostOptions" to jsonObject("attemptPairVerify" to JsonValue.of(true)),
                        "wireProtocolVersion" to JsonValue.of(HostIdentity.WIRE_PROTOCOL_VERSION),
                    )),
                )),
            ))
            val handshake = stream.receivePlain()
            if (handshake.path("response", "_1", "handshake", "_0") == null) {
                throw RpProtocolException("device did not return an RPPairing handshake response")
            }

            val ephemeral = X25519.generate()
            sendPairingData(stream, true, Tlv8.Builder()
                .add(PairingComponent.STATE, 1)
                .add(PairingComponent.PUBLIC_KEY, ephemeral.publicKey)
                .build())

            val m2 = receivePairingData(stream, "pair-verify M2")
            rejectError(m2)
            expectState(m2, 2)
            val devicePublic = Tlv8.value(m2, PairingComponent.PUBLIC_KEY)
            require(devicePublic.size == X25519.KEY_BYTES) { "pair verify M2 public key size=${devicePublic.size}" }

            val sharedSecret = ephemeral.agree(devicePublic)
            val verifyKey = Hkdf.derive(
                Digest.SHA512,
                "Pair-Verify-Encrypt-Salt".toByteArray(),
                sharedSecret,
                "Pair-Verify-Encrypt-Info".toByteArray(),
                32,
            )
            val deviceProof = ChaChaPoly.open(
                verifyKey,
                ChaChaPoly.nonce("PV-Msg02"),
                Tlv8.value(m2, PairingComponent.ENCRYPTED_DATA),
            )
            val proof = Tlv8.decode(deviceProof)
            val deviceIdentifier = String(Tlv8.value(proof, PairingComponent.IDENTIFIER))
            val deviceSignature = Tlv8.value(proof, PairingComponent.SIGNATURE)
            val deviceSigned = devicePublic + deviceIdentifier.toByteArray() + ephemeral.publicKey
            if (!Ed25519.verify(record.peer.longTermPublicKey, deviceSigned, deviceSignature)) {
                throw RpProtocolException("device identity signature did not match stored pairing")
            }
            Log.i(LogTag.PAIRING, "device identity verified for ${record.peer.name}")

            val hostSigned = ephemeral.publicKey + identity.identifier.toByteArray() + devicePublic
            val hostSignature = identity.signingKey.sign(hostSigned)
            val hostProof = Tlv8.Builder()
                .add(PairingComponent.IDENTIFIER, identity.identifier)
                .add(PairingComponent.SIGNATURE, hostSignature)
                .build()
            sendPairingData(
                stream,
                false,
                Tlv8.Builder()
                    .add(PairingComponent.STATE, 3)
                    .add(PairingComponent.ENCRYPTED_DATA, ChaChaPoly.seal(
                        verifyKey, ChaChaPoly.nonce("PV-Msg03"), hostProof,
                    ))
                    .build(),
            )

            val m4 = receivePairingData(stream, "pair-verify M4")
            rejectError(m4)
            expectState(m4, 4)
            val session = VerifiedSession(record, SessionKeys.fromSharedSecret(sharedSecret), sharedSecret)
            val listenerPort = createListener(stream, session)
            Log.i(LogTag.PAIRING, "pair-verify + createListener completed for ${record.peer.name} port=$listenerPort")
            return Result(session, listenerPort)
        }
    }

    private fun sendPairingData(stream: RpPairingStream, startNewSession: Boolean, payload: ByteArray) {
        stream.sendPlain(jsonObject("event" to jsonObject("_0" to jsonObject(
            "pairingData" to jsonObject("_0" to jsonObject(
                "data" to JsonValue.of(Base64.getEncoder().encodeToString(payload)),
                "kind" to JsonValue.of("verifyManualPairing"),
                "startNewSession" to JsonValue.of(startNewSession),
            )),
        ))))
    }

    private fun receivePairingData(stream: RpPairingStream, label: String): List<Tlv8.Entry> {
        val message = stream.receivePlain()
        val encoded = message.path("event", "_0", "pairingData", "_0", "data")?.asText
            ?: throw RpProtocolException("${label} did not contain pairingData")
        return try {
            Tlv8.decode(Base64.getDecoder().decode(encoded))
        } catch (e: IllegalArgumentException) {
            throw RpProtocolException("${label} pairingData was not base64")
        }
    }

    private fun createListener(stream: RpPairingStream, session: VerifiedSession): Int {
        val key = Base64.getEncoder().encodeToString(session.sharedSecret)
        val request = JsonValue.parse(
            """{"request":{"_0":{"createListener":{"key":"$key","transportProtocolType":"tcp"}}}}""",
        )
        stream.sendEncrypted(ChaChaPoly.seal(
            session.keys.writeKey,
            ChaChaPoly.nonce(0L),
            request.encode().toByteArray(),
        ))
        val reply = stream.receive()
        val json = when (reply) {
            is RpMessage.Plain -> throw RpProtocolException("createListener response was not encrypted")
            is RpMessage.Encrypted -> JsonValue.parse(String(ChaChaPoly.open(
                session.keys.readKey, ChaChaPoly.nonce(0L), reply.ciphertext,
            )))
        }
        val port = json.path("createListener", "port")?.asLong
            ?: json.path("response", "_0", "createListener", "port")?.asLong
            ?: throw RpProtocolException("createListener response had no port: ${json.encode().take(300)}")
        require(port in 1..65535) { "invalid createListener port $port" }
        return port.toInt()
    }

    private fun expectState(entries: List<Tlv8.Entry>, expected: Int) {
        val state = Tlv8.byte(entries, PairingComponent.STATE)
        if (state != expected) throw RpProtocolException("expected pair verify state $expected but got $state")
    }

    private fun rejectError(entries: List<Tlv8.Entry>) {
        if (!Tlv8.contains(entries, PairingComponent.ERROR)) return
        val code = Tlv8.byte(entries, PairingComponent.ERROR)
        throw RpProtocolException("device reported pair verify error ${code?.let { PairingError.of(it) } ?: code}")
    }
}