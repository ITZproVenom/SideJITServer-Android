package dev.sidejit.core.net

import java.net.ServerSocket

object Ports {
    /**
     * Asks the operating system for an unused TCP port and gives it straight back.
     * There is an unavoidable race between closing the probe socket and binding for
     * real, so callers should prefer binding to port 0 and reading the result. This
     * exists for the cases where a port has to be known before the listener starts.
     */
    fun freeTcpPort(): Int = ServerSocket(0).use { it.localPort }
}