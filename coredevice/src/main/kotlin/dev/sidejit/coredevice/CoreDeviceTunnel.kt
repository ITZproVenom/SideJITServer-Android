package dev.sidejit.coredevice

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.pairing.SessionKeys
import dev.sidejit.pairing.VerifiedSession
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.util.Base64

/**
 * Opens a CoreDevice tunnel after pair-verify:
 * 1. createListener (TCP) on the control channel — caller supplies the already-verified stream path
 * 2. TLS-PSK to host:port returned by the device
 * 3. CDTunnel clientHandshakeRequest / serverHandshakeResponse
 *
 * Returns [OpenedTunnel] with the TLS streams and negotiated RSD endpoint.
 * Userspace TCP to that RSD address is a separate step ([UserspaceEndpoint]).
 */
object CoreDeviceTunnel {

    class TunnelException(message: String, cause: Throwable? = null) : Exception(message, cause)

    data class OpenedTunnel(
        val session: TlsPskClient.TlsSession,
        val parameters: TunnelParameters,
        val input: InputStream,
        val output: OutputStream,
    ) : AutoCloseable {
        override fun close() = session.close()
    }

    fun createListenerRequest(session: VerifiedSession): String {
        val key = CreateListener.keyFromSession(session.sharedSecret)
        return CreateListener.tcpRequest(key).encode()
    }

    fun createListenerRequest(keys: SessionKeys): String {
        val key = Base64.getEncoder().encodeToString(keys.writeKey)
        return CreateListener.tcpRequest(key).encode()
    }

    /**
     * Complete the data-plane side: TLS-PSK + CDTunnel handshake.
     * [host] is the device address used for the TCP connect (usually the same host as pairing).
     * [listenerPort] comes from createListener response.
     * [psk] is the pair-verify shared secret (or the key sent in createListener).
     */
    fun openDataPlane(
        host: String,
        listenerPort: Int,
        psk: ByteArray,
    ): OpenedTunnel {
        // Deliberately not cleared: a failed launch rebuilds the tunnel, and wiping the trace
        // here would throw away the evidence of why the previous attempt failed.
        TunnelDiagnostics.record("--- TLS-PSK connect to $host:$listenerPort")
        Log.i(LogTag.TUNNEL, "TLS-PSK connect $host:$listenerPort")
        val tls = TlsPskClient(psk).connect(host, listenerPort)
        try {
            CdTunnel.writeJson(tls.output, ClientHandshake.request())
            val responsePacket = CdTunnel.read(tls.input)
            val json = JsonValue.parse(String(responsePacket.body, Charsets.UTF_8))
            val params = TunnelParameters.fromHandshakeResponse(json)
            Log.i(
                LogTag.TUNNEL,
                "tunnel up client=${params.clientAddress} server=${params.serverAddress} rsd=${params.serverRsdPort}",
            )
            TunnelDiagnostics.record(
                "tunnel up: we are ${params.clientAddress}, the device is ${params.serverAddress}, " +
                    "rsd port ${params.serverRsdPort}, mtu ${params.mtu}",
            )
            // Short reads from here on, so the data plane can retransmit instead of blocking
            // for the whole connect timeout on one read.
            tls.readTimeout(500)
            return OpenedTunnel(tls, params, tls.input, tls.output)
        } catch (failure: Exception) {
            TunnelDiagnostics.record("CDTunnel handshake failed: ${failure.message}")
            tls.close()
            throw TunnelException("CDTunnel handshake failed: ${failure.message}", failure)
        }
    }

    /** Convenience that still needs a live createListener exchange on the control channel. */
    fun open(session: VerifiedSession, deviceHost: String, listenerPort: Int): OpenedTunnel =
        openDataPlane(deviceHost, listenerPort, session.sharedSecret)

    fun open(session: VerifiedSession): Nothing =
        throw TunnelException(
            "open(session) needs deviceHost + listenerPort from createListener; " +
                "use open(session, host, port) after the control-channel createListener exchange",
        )

    fun open(keys: SessionKeys): Nothing =
        throw TunnelException("open(keys) needs host and listener port from createListener")
}

/** Placeholder for mapping a tunnel virtual address to a local TCP endpoint. */
data class UserspaceEndpoint(
    val address: InetAddress,
    val port: Int,
)
