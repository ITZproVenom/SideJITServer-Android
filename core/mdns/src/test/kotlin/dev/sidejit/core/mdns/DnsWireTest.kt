package dev.sidejit.core.mdns

import java.net.InetAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsNameTest {
    @Test
    fun `a dotted name splits into labels`() {
        assertEquals(listOf("host", "local"), DnsName("host.local.").labels)
        assertEquals(listOf("host", "local"), DnsName("host.local").labels)
    }

    @Test
    fun `the root name has no labels`() {
        assertEquals(emptyList<String>(), DnsName(".").labels)
        assertEquals(".", DnsName(".").dotted)
    }

    @Test
    fun `comparison ignores case as dns requires`() {
        assertEquals(DnsName("Host.Local"), DnsName("host.local"))
        assertEquals(DnsName("Host.Local").hashCode(), DnsName("host.local").hashCode())
        assertNotEquals(DnsName("host.local"), DnsName("other.local"))
    }

    @Test
    fun `suffix matching works on label boundaries`() {
        assertTrue(DnsName("a._tcp.local").endsWith(DnsName("_tcp.local")))
        assertFalse(DnsName("a._tcp.local").endsWith(DnsName("tcp.local")))
        assertFalse(DnsName("local").endsWith(DnsName("a.local")))
    }
}

class DnsWireTest {
    @Test
    fun `a name round trips`() {
        val writer = DnsWriter()
        writer.name(DnsName("SideJIT._remotepairing-pairable-host._tcp.local"))
        val reader = DnsReader(writer.toByteArray())
        assertEquals(DnsName("SideJIT._remotepairing-pairable-host._tcp.local"), reader.name())
    }

    @Test
    fun `a repeated suffix is compressed`() {
        val uncompressed = DnsWriter().apply { name(DnsName("a._tcp.local")) }.toByteArray().size
        val writer = DnsWriter()
        writer.name(DnsName("a._tcp.local"))
        writer.name(DnsName("b._tcp.local"))
        // The second name costs one label plus a two byte pointer, never the full name.
        assertTrue(writer.toByteArray().size < uncompressed * 2)
        val reader = DnsReader(writer.toByteArray())
        assertEquals(DnsName("a._tcp.local"), reader.name())
        assertEquals(DnsName("b._tcp.local"), reader.name())
    }

    @Test(expected = DnsFormatException::class)
    fun `a pointer loop is refused`() {
        // A name at offset zero whose pointer targets offset zero.
        DnsReader(byteArrayOf(0xC0.toByte(), 0x00)).name()
    }

    @Test(expected = DnsFormatException::class)
    fun `a pointer past the end is refused`() {
        DnsReader(byteArrayOf(0xC0.toByte(), 0x7F)).name()
    }

    @Test(expected = DnsFormatException::class)
    fun `a label running past the end is refused`() {
        DnsReader(byteArrayOf(0x05, 0x61, 0x62)).name()
    }

    @Test(expected = DnsFormatException::class)
    fun `a label longer than the limit is refused when writing`() {
        DnsWriter().name(DnsName("x".repeat(64) + ".local"))
    }

    @Test
    fun `integers round trip at their declared widths`() {
        val writer = DnsWriter().u8(0xAB).u16(0xBEEF).u32(0xDEADBEEFL)
        val reader = DnsReader(writer.toByteArray())
        assertEquals(0xAB, reader.u8())
        assertEquals(0xBEEF, reader.u16())
        assertEquals(0xDEADBEEFL, reader.u32())
    }
}

class DnsMessageTest {
    private val host = DnsName("idevice-0123abcd.local")
    private val full = DnsName("SideJIT._remotepairing-pairable-host._tcp.local")

    @Test
    fun `a query round trips`() {
        val message = DnsMessage(
            id = 0,
            questions = listOf(DnsQuestion(DnsName("_remotepairing-pairable-host._tcp.local"), DnsType.PTR)),
        )
        val decoded = DnsMessage.decode(message.encode())
        assertEquals(1, decoded.questions.size)
        assertEquals(DnsType.PTR, decoded.questions[0].type)
        assertFalse(decoded.response)
    }

    @Test
    fun `the unicast response bit survives a round trip`() {
        val message = DnsMessage(questions = listOf(DnsQuestion(full, DnsType.SRV, unicastResponse = true)))
        val decoded = DnsMessage.decode(message.encode())
        assertTrue(decoded.questions[0].unicastResponse)
        assertEquals(DnsClass.IN, decoded.questions[0].dnsClass)
    }

    @Test
    fun `every record type round trips`() {
        val original = DnsMessage(
            response = true,
            answers = listOf(
                DnsRecord.Pointer(DnsName("_remotepairing-pairable-host._tcp.local"), full),
                DnsRecord.Service(full, host, 49152),
                DnsRecord.Text(full, linkedMapOf("model" to "AndroidTV", "flags" to "1")),
                DnsRecord.Address(host, InetAddress.getByName("192.168.1.22")),
                DnsRecord.Address(host, InetAddress.getByName("fe80::1")),
            ),
        )
        val decoded = DnsMessage.decode(original.encode())
        assertEquals(5, decoded.answers.size)
        assertEquals(original.answers[0], decoded.answers[0])
        assertEquals(original.answers[1], decoded.answers[1])
        assertEquals(original.answers[2], decoded.answers[2])
        assertEquals(original.answers[3], decoded.answers[3])
        assertEquals(original.answers[4], decoded.answers[4])
        assertTrue(decoded.response)
    }

    @Test
    fun `the cache flush bit survives a round trip`() {
        val message = DnsMessage(
            response = true,
            answers = listOf(DnsRecord.Service(full, host, 1234, cacheFlush = true)),
        )
        assertTrue((DnsMessage.decode(message.encode()).answers[0] as DnsRecord.Service).cacheFlush)
    }

    @Test
    fun `an empty text record encodes as one empty string`() {
        val message = DnsMessage(response = true, answers = listOf(DnsRecord.Text(full, emptyMap())))
        val decoded = DnsMessage.decode(message.encode())
        assertEquals(emptyMap<String, String>(), (decoded.answers[0] as DnsRecord.Text).entries)
    }

    @Test
    fun `a text entry without a value keeps its key`() {
        val message = DnsMessage(response = true, answers = listOf(DnsRecord.Text(full, mapOf("flag" to ""))))
        val decoded = DnsMessage.decode(message.encode())
        assertEquals(mapOf("flag" to ""), (decoded.answers[0] as DnsRecord.Text).entries)
    }

    @Test
    fun `an unknown record type is preserved as opaque data`() {
        val payload = byteArrayOf(1, 2, 3, 4)
        val message = DnsMessage(response = true, answers = listOf(DnsRecord.Opaque(host, 99, payload, 10)))
        val decoded = DnsMessage.decode(message.encode()).answers[0] as DnsRecord.Opaque
        assertEquals(99, decoded.type)
        assertArrayEquals(payload, decoded.data)
    }

    @Test(expected = DnsFormatException::class)
    fun `a truncated packet is refused`() {
        val encoded = DnsMessage(questions = listOf(DnsQuestion(full, DnsType.SRV))).encode()
        DnsMessage.decode(encoded.copyOf(encoded.size - 3))
    }

    @Test(expected = DnsFormatException::class)
    fun `a record claiming more data than the packet holds is refused`() {
        val encoded = DnsMessage(
            response = true,
            answers = listOf(DnsRecord.Address(host, InetAddress.getByName("10.0.0.1"))),
        ).encode()
        DnsMessage.decode(encoded.copyOf(encoded.size - 2))
    }
}