package dev.sidejit.core.mdns

import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the record folding the browser does, without touching the network.
 *
 * The parts that need a link - sending the question and reading datagrams - cannot be tested
 * here. Only the decoding of what comes back is.
 */
class MdnsBrowserTest {

    private val serviceType = DnsName("_remotepairing._tcp.local")
    private val instance = DnsName("ABC123._remotepairing._tcp.local")
    private val target = DnsName("iPhone.local")

    private fun fold(message: DnsMessage, source: InetAddress?): List<DiscoveredService> {
        val partials = LinkedHashMap<DnsName, MdnsBrowser.Partial>()
        MdnsBrowser.collect(message, source, serviceType, partials)
        return MdnsBrowser.assemble(partials)
    }

    @Test
    fun `folds a complete reply into one service`() {
        val message = DnsMessage(
            response = true,
            answers = listOf(DnsRecord.Pointer(serviceType, instance)),
            additional = listOf(
                DnsRecord.Service(instance, target, 49_152),
                DnsRecord.Text(instance, linkedMapOf("authTag" to "dGFn", "name" to "iPhone")),
                DnsRecord.Address(target, InetAddress.getByName("192.168.1.42")),
            ),
        )
        val services = fold(message, InetAddress.getByName("192.168.1.42"))
        assertEquals(1, services.size)
        val service = services.single()
        assertEquals("ABC123", service.instanceName)
        assertEquals("_remotepairing._tcp.local", service.serviceType)
        assertEquals(49_152, service.port)
        assertEquals("dGFn", service.txtRecords["authTag"])
        assertTrue(service.addresses.contains(InetAddress.getByName("192.168.1.42")))
    }

    @Test
    fun `ignores an instance that never produced an SRV record`() {
        val message = DnsMessage(
            response = true,
            answers = listOf(DnsRecord.Pointer(serviceType, instance)),
            additional = listOf(DnsRecord.Text(instance, linkedMapOf("authTag" to "dGFn"))),
        )
        assertTrue(fold(message, null).isEmpty())
    }

    @Test
    fun `ignores records for another service type`() {
        val other = DnsName("Printer._ipp._tcp.local")
        val message = DnsMessage(
            response = true,
            answers = listOf(DnsRecord.Pointer(DnsName("_ipp._tcp.local"), other)),
            additional = listOf(DnsRecord.Service(other, target, 631)),
        )
        assertTrue(fold(message, null).isEmpty())
    }

    @Test
    fun `survives replies that arrive in separate datagrams`() {
        val partials = LinkedHashMap<DnsName, MdnsBrowser.Partial>()
        MdnsBrowser.collect(
            DnsMessage(response = true, answers = listOf(DnsRecord.Pointer(serviceType, instance))),
            null,
            serviceType,
            partials,
        )
        assertTrue(MdnsBrowser.assemble(partials).isEmpty())
        MdnsBrowser.collect(
            DnsMessage(
                response = true,
                answers = listOf(DnsRecord.Service(instance, target, 61_000)),
                additional = listOf(
                    DnsRecord.Text(instance, linkedMapOf("ver" to "26")),
                    DnsRecord.Address(target, InetAddress.getByName("10.0.0.5")),
                ),
            ),
            null,
            serviceType,
            partials,
        )
        val service = MdnsBrowser.assemble(partials).single()
        assertEquals(61_000, service.port)
        assertEquals("26", service.txtRecords["ver"])
        assertEquals(listOf<InetAddress>(InetAddress.getByName("10.0.0.5")), service.addresses)
    }

    @Test
    fun `always keeps the datagram source as a candidate address`() {
        // A responder that omits AAAA records still has to be reachable, and the source address
        // of its reply is the one address we know works.
        val source = InetAddress.getByName("192.168.1.9")
        val message = DnsMessage(
            response = true,
            answers = listOf(
                DnsRecord.Pointer(serviceType, instance),
                DnsRecord.Service(instance, target, 50_000),
            ),
        )
        assertEquals(listOf(source), fold(message, source).single().addresses)
    }

    @Test
    fun `borrows the IPv6 scope from the datagram source`() {
        // AAAA records carry sixteen bytes and no scope id, so a link local address decoded from
        // the wire cannot be connected to. The scope has to come from the packet.
        val nic = NetworkInterface.getNetworkInterfaces().toList().firstOrNull {
            it.inetAddresses.toList().any { address -> address is Inet6Address }
        } ?: return
        val scopedSource = Inet6Address.getByAddress(
            null,
            InetAddress.getByName("fe80::1").address,
            nic,
        )
        val unscoped = InetAddress.getByName("fe80::1c43:5a3b:2960:84e2")
        val restored = MdnsBrowser.scoped(unscoped, scopedSource)
        assertTrue(restored is Inet6Address)
        assertEquals(nic, (restored as Inet6Address).scopedInterface)
        assertTrue(restored.hostAddress!!.contains("%"))
    }

    @Test
    fun `leaves routable addresses alone`() {
        val routable = InetAddress.getByName("2001:db8::1")
        assertEquals(routable, MdnsBrowser.scoped(routable, InetAddress.getByName("2001:db8::2")))
        val v4 = InetAddress.getByName("192.168.1.1")
        assertEquals(v4, MdnsBrowser.scoped(v4, InetAddress.getByName("192.168.1.2")))
        assertFalse(MdnsBrowser.scoped(v4, null) is Inet6Address)
    }
}
