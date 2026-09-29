package dev.sidejit.core.mdns

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.core.net.Interfaces
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A multicast DNS responder that only answers for the services it was given.
 * It does not implement a resolver or a cache; nothing here needs to browse.
 *
 * Two sockets are used, one per address family, because a single socket cannot be
 * joined to both groups portably. Either may be absent on a network that lacks that
 * family, and the responder keeps working with whichever one came up.
 */
class MdnsResponder(
    private val services: List<ServiceRegistration>,
) {
    private val running = AtomicBoolean(false)
    private var ipv4Socket: MulticastSocket? = null
    private var ipv6Socket: MulticastSocket? = null
    private var readers = mutableListOf<Thread>()
    private var joined = emptyList<NetworkInterface>()

    private val records = ServiceRecords(services) { service ->
        // Addresses are read fresh on every use so a network change is picked up even
        // between re-registrations.
        Interfaces.addresses()
            .map { it.address }
            .filter { !it.isLoopbackAddress }
            .filter { it !is Inet6Address || !it.isMulticastAddress }
            .also { if (it.isEmpty()) Log.w(LogTag.MDNS, "no address to advertise for ${service.instanceName}") }
            .distinct()
    }

    val isRunning: Boolean get() = running.get()

    @Synchronized
    fun start() {
        if (!running.compareAndSet(false, true)) return
        joined = Interfaces.multicastCapable()
        if (joined.isEmpty()) {
            Log.w(LogTag.MDNS, "no multicast capable interface, the responder will not be reachable")
        }
        ipv4Socket = openSocket(IPV4_GROUP)
        ipv6Socket = openSocket(IPV6_GROUP)
        if (ipv4Socket == null && ipv6Socket == null) {
            running.set(false)
            throw IllegalStateException("no multicast socket could be opened")
        }
        ipv4Socket?.let { socket -> readers.add(readerThread("mdns-v4", socket)) }
        ipv6Socket?.let { socket -> readers.add(readerThread("mdns-v6", socket)) }
        announce()
        Log.i(LogTag.MDNS, "responder started for ${services.joinToString { it.fullName.dotted }}")
    }

    @Synchronized
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        try {
            send(DnsMessage(response = true, answers = records.goodbye()))
        } catch (failure: Exception) {
            Log.d(LogTag.MDNS, "could not send the goodbye packet: ${failure.describe()}")
        }
        ipv4Socket?.close()
        ipv6Socket?.close()
        ipv4Socket = null
        ipv6Socket = null
        readers.forEach { it.join(1000) }
        readers.clear()
        Log.i(LogTag.MDNS, "responder stopped")
    }

    /**
     * Re-announces the current record set. Call this when the network changes; the
     * cache flush bit on our records makes listeners replace what they had.
     */
    fun announce() {
        val message = DnsMessage(response = true, answers = records.announcement())
        send(message)
    }

    private fun openSocket(group: InetAddress): MulticastSocket? = try {
        val socket = MulticastSocket(null)
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(PORT))
        socket.timeToLive = 255
        socket.soTimeout = 1000
        var anyJoin = false
        for (candidate in joined) {
            val families = candidate.inetAddresses.asSequence().toList()
            val matches = if (group is Inet4Address) {
                families.any { it is Inet4Address }
            } else {
                families.any { it is Inet6Address }
            }
            if (!matches) continue
            try {
                socket.joinGroup(InetSocketAddress(group, PORT), candidate)
                anyJoin = true
            } catch (failure: Exception) {
                Log.d(LogTag.MDNS, "could not join $group on ${candidate.name}: ${failure.message}")
            }
        }
        if (!anyJoin) {
            socket.close()
            null
        } else {
            socket
        }
    } catch (failure: Exception) {
        Log.w(LogTag.MDNS, "could not open a socket for $group: ${failure.describe()}")
        null
    }

    private fun readerThread(name: String, socket: MulticastSocket): Thread =
        Thread({ readLoop(socket) }, name).apply {
            isDaemon = true
            start()
        }

    private fun readLoop(socket: MulticastSocket) {
        val buffer = ByteArray(9000)
        while (running.get() && !socket.isClosed) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (timeout: SocketTimeoutException) {
                continue
            } catch (failure: Exception) {
                if (running.get()) Log.d(LogTag.MDNS, "receive failed: ${failure.describe()}")
                continue
            }
            val query = try {
                DnsMessage.decode(packet.data, packet.length)
            } catch (malformed: DnsFormatException) {
                Log.d(LogTag.MDNS, "ignoring a malformed packet: ${malformed.message}")
                continue
            }
            handle(query, socket, packet.address, packet.port)
        }
    }

    private fun handle(query: DnsMessage, socket: MulticastSocket, from: InetAddress, fromPort: Int) {
        if (query.response || query.questions.isEmpty()) return
        val answers = LinkedHashSet<DnsRecord>()
        val additional = LinkedHashSet<DnsRecord>()
        var unicast = false
        for (question in query.questions) {
            val (direct, extra) = records.respondTo(question)
            if (direct.isEmpty()) continue
            if (question.unicastResponse || fromPort != PORT) unicast = true
            for (record in direct) {
                if (!records.isSuppressedBy(record, query.answers)) answers.add(record)
            }
            additional.addAll(extra)
        }
        if (answers.isEmpty()) return
        val response = DnsMessage(
            id = if (unicast) query.id else 0,
            response = true,
            answers = answers.toList(),
            additional = additional.filter { it !in answers },
        )
        val payload = response.encode()
        try {
            if (unicast) {
                socket.send(DatagramPacket(payload, payload.size, from, fromPort))
            } else {
                sendOn(socket, payload)
            }
        } catch (failure: Exception) {
            Log.d(LogTag.MDNS, "could not send a response: ${failure.describe()}")
        }
    }

    private fun send(message: DnsMessage) {
        val payload = message.encode()
        ipv4Socket?.let { runCatching { sendOn(it, payload) } }
        ipv6Socket?.let { runCatching { sendOn(it, payload) } }
    }

    private fun sendOn(socket: MulticastSocket, payload: ByteArray) {
        val group = if (socket === ipv6Socket) IPV6_GROUP else IPV4_GROUP
        val packet = DatagramPacket(payload, payload.size, group, PORT)
        if (joined.isEmpty()) {
            socket.send(packet)
            return
        }
        for (candidate in joined) {
            try {
                socket.networkInterface = candidate
                socket.send(packet)
            } catch (failure: Exception) {
                Log.d(LogTag.MDNS, "send on ${candidate.name} failed: ${failure.message}")
            }
        }
    }

    companion object {
        const val PORT: Int = 5353
        val IPV4_GROUP: InetAddress = InetAddress.getByName("224.0.0.251")
        val IPV6_GROUP: InetAddress = InetAddress.getByName("ff02::fb")
    }
}