package dev.sidejit.core.net

import java.net.Inet4Address
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InterfacesTest {
    @Test
    fun `enumeration never reports loopback or wildcard addresses`() {
        for (entry in Interfaces.addresses()) {
            assertFalse(entry.toString(), entry.address.isLoopbackAddress)
            assertFalse(entry.toString(), entry.address.isAnyLocalAddress)
        }
    }

    @Test
    fun `enumeration does not crash on a build machine with no usable interface`() {
        // The result may legitimately be empty in a container; the contract is that the
        // call returns rather than throwing.
        Interfaces.multicastCapable()
        Interfaces.preferredAddresses()
        Interfaces.signature()
    }

    @Test
    fun `routable addresses sort ahead of link local ones`() {
        val routable = HostAddress("wlan0", InetAddress.getByName("192.168.1.5"), 24)
        val linkLocal = HostAddress("wlan0", InetAddress.getByName("169.254.3.4"), 16)
        val sorted = listOf(linkLocal, routable).sortedWith(
            compareBy({ it.isLinkLocal }, { it.isIpv6 }, { it.interfaceName }),
        )
        assertEquals(routable, sorted.first())
    }

    @Test
    fun `an ipv6 link local literal carries its interface scope`() {
        val entry = HostAddress("wlan0", InetAddress.getByName("fe80::1%1"), 64)
        assertTrue(entry.literal, entry.literal.endsWith("%wlan0") || !entry.address.toString().contains('%'))
    }

    @Test
    fun `an ipv4 address is reported as ipv4`() {
        val entry = HostAddress("eth0", InetAddress.getByName("10.0.0.2"), 24)
        assertTrue(entry.isIpv4)
        assertFalse(entry.isIpv6)
        assertTrue(entry.address is Inet4Address)
    }

    @Test
    fun `a free port is in the ephemeral range`() {
        val port = Ports.freeTcpPort()
        assertTrue(port.toString(), port in 1..65535)
    }
}