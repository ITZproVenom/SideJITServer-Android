package dev.sidejit.core.mdns

import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException

/**
 * One service instance seen on the local link.
 *
 * [addresses] is never empty: even when a responder omits the A/AAAA records we fall back to the
 * source address of the datagram, which is the only address that carries a usable IPv6 scope.
 */
data class DiscoveredService(
    val instanceName: String,
    val serviceType: String,
    val port: Int,
    val addresses: List<InetAddress>,
    val txtRecords: Map<String, String>,
)

/**
 * A one shot multicast DNS browser.
 *
 * This deliberately does not join the multicast group on port 5353, because [MdnsResponder] owns
 * that port. Instead it asks the question with the unicast response bit set from an ephemeral
 * port, which Apple's responder honours, and reads the replies straight back on that socket.
 */
object MdnsBrowser {

    private const val MDNS_PORT = 5353
    private val IPV4_GROUP: InetAddress = InetAddress.getByName("224.0.0.251")
    private val IPV6_GROUP: InetAddress = InetAddress.getByName("ff02::fb")

    /**
     * Browses [serviceType] (for example `_remotepairing._tcp.local`) for up to [timeoutMillis].
     *
     * Returns every instance that produced an SRV record, folded together with its TXT and
     * address records.
     */
    fun browse(
        serviceType: String,
        timeoutMillis: Long = 3_000,
        queryIntervalMillis: Long = 750,
    ): List<DiscoveredService> {
        val type = DnsName(normalizeType(serviceType))
        val question = DnsMessage(
            questions = listOf(
                DnsQuestion(type, DnsType.PTR, unicastResponse = true),
                DnsQuestion(type, DnsType.ANY, unicastResponse = true),
            ),
        ).encode()

        MulticastSocket(0).use { socket ->
            socket.soTimeout = 250
            socket.timeToLive = 255
            val partials = LinkedHashMap<DnsName, Partial>()
            val deadline = System.nanoTime() + timeoutMillis * 1_000_000
            var nextQuery = 0L
            val buffer = ByteArray(9000)
            while (System.nanoTime() < deadline) {
                if (System.nanoTime() >= nextQuery) {
                    send(socket, question)
                    nextQuery = System.nanoTime() + queryIntervalMillis * 1_000_000
                }
                val packet = DatagramPacket(buffer, buffer.size)
                val message = try {
                    socket.receive(packet)
                    DnsMessage.decode(packet.data, packet.length)
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: DnsFormatException) {
                    continue
                }
                collect(message, packet.address, type, partials)
            }
            return assemble(partials)
        }
    }

    private fun send(socket: MulticastSocket, question: ByteArray) {
        for (nic in interfaces()) {
            val hasV4 = addressesOf(nic).any { it is Inet4Address }
            val hasV6 = addressesOf(nic).any { it is Inet6Address }
            if (hasV4) sendTo(socket, question, IPV4_GROUP, nic)
            if (hasV6) sendTo(socket, question, IPV6_GROUP, nic)
        }
    }

    private fun sendTo(
        socket: MulticastSocket,
        question: ByteArray,
        group: InetAddress,
        nic: NetworkInterface,
    ) {
        try {
            socket.networkInterface = nic
            socket.send(DatagramPacket(question, question.size, InetSocketAddress(group, MDNS_PORT)))
        } catch (_: Exception) {
            // A single interface refusing multicast must not stop the browse.
        }
    }

    private fun interfaces(): List<NetworkInterface> =
        try {
            NetworkInterface.getNetworkInterfaces().toList().filter {
                it.isUp && it.supportsMulticast() && !it.isLoopback && addressesOf(it).isNotEmpty()
            }
        } catch (_: Exception) {
            emptyList()
        }

    private fun addressesOf(nic: NetworkInterface): List<InetAddress> =
        try {
            nic.inetAddresses.toList()
        } catch (_: Exception) {
            emptyList()
        }

    /** Record state for one instance while replies trickle in. */
    internal class Partial {
        var port: Int? = null
        var target: DnsName? = null
        val txt = LinkedHashMap<String, String>()
        val addresses = LinkedHashSet<InetAddress>()
    }

    /**
     * Folds one reply into [partials]. [source] is the datagram's source address, used both as a
     * fallback address and as the source of the IPv6 scope that AAAA records cannot carry.
     */
    internal fun collect(
        message: DnsMessage,
        source: InetAddress?,
        serviceType: DnsName,
        partials: MutableMap<DnsName, Partial>,
    ) {
        val records = message.answers + message.authority + message.additional
        val instances = LinkedHashSet<DnsName>()
        for (record in records) {
            if (record is DnsRecord.Pointer && record.name == serviceType) instances.add(record.target)
            if (record is DnsRecord.Service && record.name.endsWith(serviceType)) instances.add(record.name)
            if (record is DnsRecord.Text && record.name.endsWith(serviceType)) instances.add(record.name)
        }
        if (instances.isEmpty()) return
        for (instance in instances) partials.getOrPut(instance) { Partial() }

        // Addresses arrive keyed by host name, so index them once and hand them to each instance
        // whose SRV target matches. Link local AAAA records lose their scope on the wire, so
        // re-attach the scope from the datagram source.
        val byHost = LinkedHashMap<DnsName, MutableList<InetAddress>>()
        for (record in records) {
            if (record is DnsRecord.Address) {
                byHost.getOrPut(record.name) { ArrayList() }.add(scoped(record.address, source))
            }
        }

        for (record in records) {
            val partial = partials[record.name] ?: continue
            when (record) {
                is DnsRecord.Service -> {
                    partial.port = record.port
                    partial.target = record.target
                }
                is DnsRecord.Text -> partial.txt.putAll(record.entries)
                else -> Unit
            }
        }

        for ((instance, partial) in partials) {
            if (!instances.contains(instance)) continue
            source?.let { partial.addresses.add(it) }
            val target = partial.target
            if (target != null) partial.addresses.addAll(byHost[target].orEmpty())
            if (partial.target == null) byHost.values.forEach { partial.addresses.addAll(it) }
        }
    }

    /**
     * Copies the scope id of [source] onto [address] when [address] is an unscoped link local
     * IPv6 address. Without this a `fe80::` literal cannot be connected to on a multi homed host.
     */
    internal fun scoped(address: InetAddress, source: InetAddress?): InetAddress {
        if (address !is Inet6Address) return address
        if (!address.isLinkLocalAddress) return address
        if (address.scopeId != 0 || address.scopedInterface != null) return address
        val scope = (source as? Inet6Address)?.scopedInterface ?: return address
        return try {
            Inet6Address.getByAddress(null, address.address, scope)
        } catch (_: Exception) {
            address
        }
    }

    internal fun assemble(partials: Map<DnsName, Partial>): List<DiscoveredService> =
        partials.mapNotNull { (instance, partial) ->
            val port = partial.port ?: return@mapNotNull null
            val labels = instance.labels
            if (labels.isEmpty()) return@mapNotNull null
            DiscoveredService(
                instanceName = labels.first(),
                serviceType = labels.drop(1).joinToString("."),
                port = port,
                addresses = partial.addresses.toList(),
                txtRecords = LinkedHashMap(partial.txt),
            )
        }

    private fun normalizeType(serviceType: String): String {
        val trimmed = serviceType.trim('.')
        return if (trimmed.endsWith(".local")) trimmed else "$trimmed.local"
    }
}
