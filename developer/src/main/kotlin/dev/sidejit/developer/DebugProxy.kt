package dev.sidejit.developer

import java.io.InputStream
import java.io.OutputStream

/**
 * Runs the GDB remote attach/detach sequence on an open debugproxy stream.
 *
 * The debugproxy transport is command/response based. Sending commands without
 * consuming replies can desynchronize the stream and make a later operation
 * interpret an older response as its own.
 */
object DebugProxy {
    class DebugProxyException(message: String) : Exception(message)

    fun attachForJit(input: InputStream, output: OutputStream, pid: Long) {
        // Match StikDebug's initial debugserver channel priming.
        output.write('+'.code)
        output.write('+'.code)
        output.flush()

        command(input, output, GdbRemote.packetStartNoAck(), "QStartNoAckMode")
        command(input, output, GdbRemote.packetSetDetachOnError(), "QSetDetachOnError:1")
        command(input, output, GdbRemote.packetAttach(pid), "vAttach")
        command(input, output, GdbRemote.packetDetach(), "D")
    }

    private fun command(input: InputStream, output: OutputStream, packet: String, label: String) {
        GdbRemote.writePacket(output, packet)
        val response = try {
            GdbRemote.readPacket(input)
        } catch (failure: Exception) {
            throw DebugProxyException("debugproxy " + label + " response failed: " + failure.message)
        }
        val body = try {
            GdbRemote.decode(response)
        } catch (failure: Exception) {
            throw DebugProxyException("debugproxy " + label + " returned invalid packet: " + failure.message)
        }
        if (body.startsWith("E")) {
            throw DebugProxyException("debugproxy " + label + " returned error: " + body)
        }
    }

    fun attachForJit(bundleId: String, pid: Long): Nothing =
        throw DebugProxyException(
            "attachForJit(" + bundleId + ", " + pid + ") needs an open debugproxy InputStream/OutputStream; " +
                "use attachForJit(input, output, pid)",
        )
}
