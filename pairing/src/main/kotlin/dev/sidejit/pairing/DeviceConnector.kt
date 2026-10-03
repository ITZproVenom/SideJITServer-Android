package dev.sidejit.pairing

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.core.mdns.DiscoveredService
import dev.sidejit.core.mdns.MdnsBrowser
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Finds an already paired device on the local link and opens a verified control channel to it.
 *
 * This is the half the project was missing. Pair setup is driven by the phone, which dials into
 * our advertised pairable host service, and that leaves us as the accessory. A CoreDevice tunnel
 * can only be requested from the other direction, so to reach JIT we have to browse for the
 * device's own `_remotepairing._tcp` service, connect out to it, and verify there.
 */
object DeviceConnector {

    const val REMOTE_PAIRING_SERVICE_TYPE: String = "_remotepairing._tcp"

    class ConnectException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * A live outbound control channel.
     *
     * The socket must stay open for as long as the tunnel is wanted: iOS ties the listener it
     * creates to this session and tears it down when the connection drops.
     */
    class Connection(
        private val socket: Socket,
        val stream: RpPairingStream,
        val session: VerifiedSession,
        /** The address we actually connected to, scope id included. */
        val address: InetAddress,
        val port: Int,
        val handshake: RemotePairingClient.Handshake,
    ) : Closeable {
        val channel: RemotePairingControl.Channel = RemotePairingControl.Channel(stream, session)

        /** The literal to hand to the tunnel layer. Keeps the IPv6 scope. */
        val host: String get() = address.hostAddress ?: address.toString()

        val isOpen: Boolean get() = !socket.isClosed && socket.isConnected

        override fun close() {
            runCatching { socket.close() }
        }
    }

    /**
     * Browses for paired devices and returns the advertisements that resolve to a stored record.
     */
    fun discover(
        store: PairingStore,
        timeoutMillis: Long = 4_000,
        browse: (String, Long) -> List<DiscoveredService> = { type, timeout ->
            MdnsBrowser.browse(type, timeout)
        },
    ): List<Pair<DiscoveredService, PairingRecord>> {
        val records = store.all()
        if (records.isEmpty()) return emptyList()
        val found = browse(REMOTE_PAIRING_SERVICE_TYPE, timeoutMillis)
        Log.d(LogTag.MDNS, "browse found ${found.size} $REMOTE_PAIRING_SERVICE_TYPE instance(s)")
        return found.mapNotNull { service ->
            val record = AdvertisementMatch.firstMatch(records, service.instanceName, service.txtRecords)
            if (record == null) {
                Log.d(LogTag.MDNS, "no stored pairing resolves ${service.instanceName}")
                null
            } else {
                service to record
            }
        }
    }

    /**
     * Connects to [service], verifies [record], and returns the open channel.
     *
     * Every advertised address is tried in turn, because a device usually publishes both a
     * link local IPv6 address and a routable one and only some of them are reachable.
     */
    fun connect(
        identity: HostIdentity,
        service: DiscoveredService,
        record: PairingRecord,
        connectTimeoutMillis: Int = 4_000,
        readTimeoutMillis: Int = 20_000,
    ): Connection {
        var lastFailure: Exception? = null
        for (address in service.addresses) {
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(address, service.port), connectTimeoutMillis)
                socket.soTimeout = readTimeoutMillis
                val stream = RpPairingStream(
                    BufferedInputStream(socket.getInputStream()),
                    BufferedOutputStream(socket.getOutputStream()),
                    RpPairingStream.INITIATOR_ROLE,
                )
                val client = RemotePairingClient(identity, stream)
                val handshake = client.handshake()
                val session = client.verify(record)
                Log.i(
                    LogTag.PAIRING,
                    "verified ${record.peer.name} at ${address.hostAddress}:${service.port} as initiator",
                )
                return Connection(socket, stream, session, address, service.port, handshake)
            } catch (failure: Exception) {
                runCatching { socket.close() }
                Log.w(
                    LogTag.PAIRING,
                    "connecting to ${address.hostAddress}:${service.port} failed: ${failure.describe()}",
                )
                lastFailure = failure
            }
        }
        throw ConnectException(
            "could not verify ${record.peer.name} on any of ${service.addresses.size} address(es)",
            lastFailure,
        )
    }

    /** Discovers and connects in one step. Returns null when nothing paired is on the link. */
    fun discoverAndConnect(identity: HostIdentity, store: PairingStore, timeoutMillis: Long = 4_000): Connection? {
        var lastFailure: Exception? = null
        for ((service, record) in discover(store, timeoutMillis)) {
            try {
                return connect(identity, service, record)
            } catch (failure: Exception) {
                lastFailure = failure
            }
        }
        lastFailure?.let { throw it }
        return null
    }
}
