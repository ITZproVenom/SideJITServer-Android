package dev.sidejit.coredevice

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import org.bouncycastle.tls.BasicTlsPSKIdentity
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.PSKTlsClient
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto

/**
 * TLS 1.2 client using [CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384] (0x00A9),
 * the suite Apple's CoreDevice TCP tunnel expects on modern iOS.
 *
 * Uses Bouncy Castle's non-JSSE TLS API because Android's SSLEngine does not
 * expose pure-PSK cipher suites.
 */
class TlsPskClient(
    private val psk: ByteArray,
    private val identityHint: ByteArray = ByteArray(0),
) {
    fun connect(host: String, port: Int, timeoutMs: Int = 15_000): TlsSession {
        val socket = Socket()
        socket.tcpNoDelay = true
        socket.soTimeout = timeoutMs
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        return wrap(socket)
    }

    fun wrap(socket: Socket): TlsSession {
        val crypto = BcTlsCrypto(SecureRandom())
        val identity = BasicTlsPSKIdentity(identityHint, psk)
        val client = object : PSKTlsClient(crypto, identity) {
            override fun getSupportedVersions(): Array<ProtocolVersion> =
                ProtocolVersion.TLSv12.only()

            override fun getSupportedCipherSuites(): IntArray =
                intArrayOf(CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384)
        }
        val protocol = TlsClientProtocol(socket.getInputStream(), socket.getOutputStream())
        try {
            protocol.connect(client)
        } catch (failure: Exception) {
            runCatching { socket.close() }
            throw IOException("TLS-PSK handshake failed: ${failure.message}", failure)
        }
        return TlsSession(socket, protocol)
    }

    class TlsSession(
        private val socket: Socket,
        private val protocol: TlsClientProtocol,
    ) : AutoCloseable {
        val input: InputStream get() = protocol.inputStream
        val output: OutputStream get() = protocol.outputStream

        override fun close() {
            runCatching { protocol.close() }
            runCatching { socket.close() }
        }
    }
}
