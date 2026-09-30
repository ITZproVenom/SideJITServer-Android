package dev.sidejit.developer

import java.io.InputStream
import java.io.OutputStream

/**
 * Runs the GDB remote attach/detach sequence on an open debugproxy stream.
 */
object DebugProxy {
    class DebugProxyException(message: String) : Exception(message)

    fun attachForJit(input: InputStream, output: OutputStream, pid: Long) {
        for (packet in GdbRemote.jitAttachSequence(pid)) {
            GdbRemote.writePacket(output, packet)
            // After QStartNoAckMode, peers may still send '+' once; drain lightly.
            if (packet.contains("QStartNoAckMode")) {
                output.flush()
            }
        }
        output.flush()
    }

    fun attachForJit(bundleId: String, pid: Long): Nothing =
        throw DebugProxyException(
            "attachForJit($bundleId, $pid) needs an open debugproxy InputStream/OutputStream; " +
                "use attachForJit(input, output, pid)",
        )
}
