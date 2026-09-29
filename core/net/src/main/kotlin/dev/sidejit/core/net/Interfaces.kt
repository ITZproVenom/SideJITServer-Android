package dev.sidejit.core.net

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

/** One usable address on one interface. */
data class HostAddress(
    val interfaceName: String,
    val address: InetAddress,
    val prefixLength: Int,
) {
    val isIpv4: Boolean get() = address is Inet4Address
    val isIpv6: Boolean get() = address is Inet6Address
    val isLinkLocal: Boolean get() = address.isLinkLocalAddress

    /** The textual form, with the scope suffix an IPv6 link-local address needs. */
    val literal: String
        get() = when {
            address is Inet6Address && address.scopeId != 0 ->
                "${address.hostAddress?.substringBefore('%')}%$interfaceName"
            else -> address.hostAddress ?: address.toString()
        }

    override fun toString(): String = "$literal ($interfaceName/$prefixLength)"
}

/**
 * The interfaces we are willing to serve on. This never hardcodes an address; the
 * device has to reach us on whatever the current network happens to be.
 */
object Interfaces {
    /**
     * Interfaces that can carry multicast DNS: up, multicast capable, not loopback and
     * not point to point. A VPN or tethering interface qualifies if it meets those.
     */
    fun multicastCapable(): List<NetworkInterface> {
        val all = try {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        } catch (failure: Exception) {
            Log.w(LogTag.NETWORK, "could not enumerate network interfaces: ${failure.describe()}")
            return emptyList()
        }
        return all.filter { candidate ->
            try {
                candidate.isUp &&
                    candidate.supportsMulticast() &&
                    !candidate.isLoopback &&
                    !candidate.isPointToPoint &&
                    candidate.inetAddresses.asSequence().any()
            } catch (failure: Exception) {
                Log.d(LogTag.NETWORK, "skipping ${candidate.name}: ${failure.message}")
                false
            }
        }
    }

    /** Every address we could publish, in the order interfaces were reported. */
    fun addresses(interfaces: List<NetworkInterface> = multicastCapable()): List<HostAddress> =
        interfaces.flatMap { candidate ->
            candidate.interfaceAddresses.mapNotNull { entry ->
                val address = entry.address ?: return@mapNotNull null
                if (address.isAnyLocalAddress || address.isLoopbackAddress) return@mapNotNull null
                if (address is Inet6Address && address.isMulticastAddress) return@mapNotNull null
                HostAddress(candidate.name, address, entry.networkPrefixLength.toInt())
            }
        }

    /**
     * The addresses worth showing a user as "connect to this". Routable addresses come
     * first, IPv4 before IPv6, because that is the order a person will try them in.
     */
    fun preferredAddresses(): List<HostAddress> =
        addresses().sortedWith(
            compareBy({ it.isLinkLocal }, { it.isIpv6 }, { it.interfaceName }),
        )

    /** A short fingerprint of the current addressing, used to notice network changes. */
    fun signature(): String = addresses().map { it.toString() }.sorted().joinToString(",")
}