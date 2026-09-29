package dev.sidejit.core.mdns

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServiceRegistrationTest {
    private val service = ServiceRegistration(
        instanceName = "SideJIT",
        serviceType = "_remotepairing-pairable-host._tcp",
        hostName = "idevice-0123abcd",
        port = 49152,
        txtRecords = mapOf("model" to "AndroidTV"),
    )

    @Test
    fun `the names are assembled the way a browser expects`() {
        assertEquals("_remotepairing-pairable-host._tcp.local.", service.typeName.dotted)
        assertEquals("SideJIT._remotepairing-pairable-host._tcp.local.", service.fullName.dotted)
        assertEquals("idevice-0123abcd.local.", service.hostDnsName.dotted)
    }

    @Test
    fun `a host name that already carries a domain is left alone`() {
        assertEquals(
            "idevice-0123abcd.local.",
            service.copy(hostName = "idevice-0123abcd.local").hostDnsName.dotted,
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `an instance name longer than a label is refused`() {
        service.copy(instanceName = "x".repeat(64))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a service type without an underscore is refused`() {
        service.copy(serviceType = "remotepairing._tcp")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a port outside the valid range is refused`() {
        service.copy(port = 0)
    }
}

class ServiceRecordsTest {
    private val service = ServiceRegistration(
        instanceName = "SideJIT",
        serviceType = "_remotepairing-pairable-host._tcp",
        hostName = "idevice-0123abcd",
        port = 49152,
        txtRecords = mapOf("model" to "AndroidTV"),
    )
    private val address = InetAddress.getByName("192.168.1.22")
    private val records = ServiceRecords(listOf(service)) { listOf(address) }

    @Test
    fun `the announcement carries the enumeration pointer, the service, the text and the address`() {
        val announced = records.announcement()
        assertTrue(announced.any { it is DnsRecord.Pointer && it.name == ServiceRegistration.SERVICE_ENUMERATION })
        assertTrue(announced.any { it is DnsRecord.Pointer && it.name == service.typeName })
        assertTrue(announced.any { it is DnsRecord.Service && it.port == 49152 })
        assertTrue(announced.any { it is DnsRecord.Text })
        assertTrue(announced.any { it is DnsRecord.Address && it.address == address })
    }

    @Test
    fun `a goodbye retires every record`() {
        assertTrue(records.goodbye().all { it.ttlSeconds == 0L })
        assertEquals(records.announcement().size, records.goodbye().size)
    }

    @Test
    fun `a browse for the service type is answered with the instance and its details`() {
        val (answers, additional) = records.respondTo(DnsQuestion(service.typeName, DnsType.PTR))
        assertEquals(1, answers.size)
        assertEquals(service.fullName, (answers[0] as DnsRecord.Pointer).target)
        assertTrue(additional.any { it is DnsRecord.Service })
        assertTrue(additional.any { it is DnsRecord.Text })
        assertTrue(additional.any { it is DnsRecord.Address })
    }

    @Test
    fun `a service enumeration query lists our type`() {
        val (answers, _) = records.respondTo(
            DnsQuestion(ServiceRegistration.SERVICE_ENUMERATION, DnsType.PTR),
        )
        assertEquals(service.typeName, (answers.single() as DnsRecord.Pointer).target)
    }

    @Test
    fun `an srv query returns the port and the address as an extra`() {
        val (answers, additional) = records.respondTo(DnsQuestion(service.fullName, DnsType.SRV))
        val srv = answers.single() as DnsRecord.Service
        assertEquals(49152, srv.port)
        assertEquals(service.hostDnsName, srv.target)
        assertTrue(additional.any { it is DnsRecord.Address })
    }

    @Test
    fun `an any query on the instance returns both the service and the text`() {
        val (answers, _) = records.respondTo(DnsQuestion(service.fullName, DnsType.ANY))
        assertTrue(answers.any { it is DnsRecord.Service })
        assertTrue(answers.any { it is DnsRecord.Text })
    }

    @Test
    fun `an address query returns only the matching family`() {
        val dual = ServiceRecords(listOf(service)) {
            listOf(address, InetAddress.getByName("fe80::2"))
        }
        val (v4, _) = dual.respondTo(DnsQuestion(service.hostDnsName, DnsType.A))
        assertEquals(1, v4.size)
        assertEquals(address, (v4[0] as DnsRecord.Address).address)
        val (v6, _) = dual.respondTo(DnsQuestion(service.hostDnsName, DnsType.AAAA))
        assertEquals(1, v6.size)
    }

    @Test
    fun `a question for someone else is ignored`() {
        val (answers, additional) = records.respondTo(DnsQuestion(DnsName("printer.local"), DnsType.A))
        assertTrue(answers.isEmpty())
        assertTrue(additional.isEmpty())
    }

    @Test
    fun `a known answer with plenty of life left suppresses ours`() {
        val ours = DnsRecord.Pointer(service.typeName, service.fullName, ttlSeconds = 4500)
        val fresh = DnsRecord.Pointer(service.typeName, service.fullName, ttlSeconds = 4000)
        val stale = DnsRecord.Pointer(service.typeName, service.fullName, ttlSeconds = 100)
        assertTrue(records.isSuppressedBy(ours, listOf(fresh)))
        assertFalse(records.isSuppressedBy(ours, listOf(stale)))
    }

    @Test
    fun `a known answer for a different target does not suppress ours`() {
        val ours = DnsRecord.Pointer(service.typeName, service.fullName, ttlSeconds = 4500)
        val other = DnsRecord.Pointer(service.typeName, DnsName("Other.${service.typeName.dotted}"), 4500)
        assertFalse(records.isSuppressedBy(ours, listOf(other)))
    }

    @Test
    fun `an announcement fits in one datagram`() {
        val message = DnsMessage(response = true, answers = records.announcement())
        assertTrue(message.encode().size < DnsMessage.MAX_DATAGRAM)
    }
}