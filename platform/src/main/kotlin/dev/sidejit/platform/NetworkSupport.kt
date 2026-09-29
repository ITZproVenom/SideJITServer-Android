package dev.sidejit.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.PowerManager
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe

/**
 * Android drops multicast packets that are not addressed to the device unless an
 * application asks it not to. Without this lock the responder would transmit happily
 * and never hear a query, which looks exactly like a firewall problem.
 *
 * A wake lock is taken at the same time: a television that has been left alone for an
 * hour must still answer a phone that wants to pair.
 */
class MulticastLease(context: Context) {
    private val wifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val powerManager =
        context.applicationContext.getSystemService(Context.POWER_SERVICE) as? PowerManager

    private var multicastLock: WifiManager.MulticastLock? = null
    private var wakeLock: PowerManager.WakeLock? = null

    val isHeld: Boolean get() = multicastLock?.isHeld == true

    @Synchronized
    fun acquire() {
        if (multicastLock == null) {
            multicastLock = try {
                wifiManager?.createMulticastLock(TAG)?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
            } catch (failure: Exception) {
                Log.w(LogTag.NETWORK, "could not take the multicast lock: ${failure.describe()}")
                null
            }
            if (multicastLock == null) {
                Log.w(LogTag.NETWORK, "running without a multicast lock; discovery may not work")
            }
        }
        if (wakeLock == null) {
            wakeLock = try {
                powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG)?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
            } catch (failure: Exception) {
                Log.w(LogTag.NETWORK, "could not take the wake lock: ${failure.describe()}")
                null
            }
        }
    }

    @Synchronized
    fun release() {
        runCatching { multicastLock?.takeIf { it.isHeld }?.release() }
        runCatching { wakeLock?.takeIf { it.isHeld }?.release() }
        multicastLock = null
        wakeLock = null
    }

    private companion object {
        const val TAG = "SideJITServer"
    }
}

/**
 * Reports when the set of addresses we could be reached on has changed, so the
 * advertisement can be renewed. Wi-Fi coming back after a router restart is the common
 * case; a television moving between Ethernet and Wi-Fi is the other.
 */
class NetworkWatcher(context: Context, private val onChange: () -> Unit) {
    private val connectivityManager =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager

    private var callback: ConnectivityManager.NetworkCallback? = null

    @Synchronized
    fun start() {
        if (callback != null || connectivityManager == null) return
        val created = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = report("a network became available")
            override fun onLost(network: Network) = report("a network was lost")
            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) = report("network capabilities changed")

            private fun report(reason: String) {
                Log.d(LogTag.NETWORK, reason)
                runCatching { onChange() }
                    .onFailure { Log.w(LogTag.NETWORK, "handling a network change failed: ${it.describe()}") }
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            connectivityManager.registerNetworkCallback(request, created)
            callback = created
        } catch (failure: Exception) {
            Log.w(LogTag.NETWORK, "could not watch for network changes: ${failure.describe()}")
        }
    }

    @Synchronized
    fun stop() {
        callback?.let { runCatching { connectivityManager?.unregisterNetworkCallback(it) } }
        callback = null
    }
}