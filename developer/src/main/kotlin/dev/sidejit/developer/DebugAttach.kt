package dev.sidejit.developer

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag

/**
 * Attaches to a process and lets go again.
 *
 * On iOS the kernel marks a process as debugged (which is what permits JIT)
 * while a debugger is attached; attaching and detaching straight away is the
 * technique StikDebug and SideJITServer use.
 */
class DebugAttach(private val gdb: GdbConnection) {

    data class Outcome(val pid: Int, val stopReply: String)

    fun attachAndDetach(pid: Int): Outcome {
        require(pid > 0) { "pid must be positive" }
        gdb.startNoAckMode()
        val detachOnError = gdb.transact("QSetDetachOnError:1")
        if (detachOnError != "OK") Log.w(LogTag.GDB, "QSetDetachOnError answered '$detachOnError'")

        val stop = gdb.transact("vAttach;" + Integer.toHexString(pid))
        if (stop.startsWith("E") || stop.isEmpty()) {
            throw GdbProtocolException("vAttach failed: '$stop'")
        }
        if (!(stop.startsWith("T") || stop.startsWith("S") || stop.startsWith("W"))) {
            throw GdbProtocolException("unexpected attach reply: '$stop'")
        }
        Log.i(LogTag.GDB, "attached to pid $pid")

        // Detach. debugserver answers OK and then closes; a closed socket
        // straight after the request is also a successful detach.
        val detach = try {
            gdb.transact("D")
        } catch (closed: GdbProtocolException) {
            if (closed.message?.contains("closed") == true) "OK" else throw closed
        }
        if (detach != "OK") throw GdbProtocolException("detach refused: '$detach'")
        Log.i(LogTag.GDB, "detached from pid $pid")
        return Outcome(pid, stop)
    }
}
