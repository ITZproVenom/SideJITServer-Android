package dev.sidejit.developer

import dev.sidejit.coredevice.Http2
import dev.sidejit.coredevice.RemoteXpc
import dev.sidejit.coredevice.Rsd
import dev.sidejit.coredevice.TunnelParameters
import dev.sidejit.coredevice.UserspaceTcp
import java.io.InputStream
import java.io.OutputStream

/**
 * DVT ProcessControl client over RemoteXPC (HTTP/2 DATA frames carrying NSKeyedArchive).
 * Sends launchSuspended archive; best-effort reads a response frame for a PID hint.
 * Live reply shape is device-dependent — PID extraction is heuristic only.
 */
class DvtClient(
    private val input: InputStream,
    private val output: OutputStream,
    private val tcp: UserspaceTcp.TcpStream? = null,
) : AutoCloseable {
    class DvtException(message: String, cause: Throwable? = null) : Exception(message, cause)

    data class LaunchResult(val pid: Long?, val rawHint: String?)

    fun openChannel() {
        RemoteXpc.writePreface(output)
        // Drain optional SETTINGS/WINDOW_UPDATE from peer.
        try {
            if (input.available() > 0) {
                val frame = Http2.readFrame(input)
                if (frame.type == Http2.FRAME_SETTINGS && frame.flags and Http2.FLAG_ACK == 0) {
                    output.write(Http2.settingsFrame(ack = true))
                    output.flush()
                }
            }
        } catch (_: Exception) {
        }
    }

    fun sendArchive(payload: ByteArray, streamId: Int = 1) {
        output.write(Http2.encodeFrame(Http2.FRAME_DATA, Http2.FLAG_END_STREAM, streamId, payload))
        output.flush()
    }

    /**
     * Send launchSuspended and attempt to read one response DATA frame.
     * Returns a PID only when a clear integer can be scraped from the payload;
     * otherwise pid is null (caller must not claim success).
     */
    fun launchSuspended(bundleId: String): LaunchResult {
        openChannel()
        sendArchive(ProcessControl.launchSuspendedArchive(bundleId))
        return tryReadPid()
    }

    private fun tryReadPid(): LaunchResult {
        return try {
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline) {
                if (input.available() <= 0) {
                    Thread.sleep(50)
                    continue
                }
                val frame = Http2.readFrame(input)
                if (frame.type != Http2.FRAME_DATA || frame.payload.isEmpty()) continue
                val hint = String(frame.payload, Charsets.UTF_8)
                val pid = scrapePid(frame.payload) ?: scrapePid(hint.toByteArray())
                return LaunchResult(pid, hint.take(200))
            }
            LaunchResult(null, "no DVT DATA reply within 5s")
        } catch (e: Exception) {
            LaunchResult(null, "DVT reply read failed: ${e.message}")
        }
    }

    private fun scrapePid(bytes: ByteArray): Long? {
        // Heuristic: look for ASCII decimal sequences that look like PIDs (1..999999).
        val text = runCatching { String(bytes, Charsets.UTF_8) }.getOrNull() ?: return null
        val re = Regex("""(?<![0-9])([1-9][0-9]{0,5})(?![0-9])""")
        for (m in re.findAll(text)) {
            val n = m.groupValues[1].toLongOrNull() ?: continue
            if (n in 1..999_999) return n
        }
        // Also scan little-endian 4-byte ints in plausible range.
        if (bytes.size >= 4) {
            var i = 0
            while (i + 4 <= bytes.size) {
                val n = (bytes[i].toInt() and 0xFF) or
                    ((bytes[i + 1].toInt() and 0xFF) shl 8) or
                    ((bytes[i + 2].toInt() and 0xFF) shl 16) or
                    ((bytes[i + 3].toInt() and 0xFF) shl 24)
                val u = n.toLong() and 0xFFFFFFFFL
                if (u in 1..999_999) return u
                i++
            }
        }
        return null
    }

    override fun close() {
        runCatching { tcp?.close() }
    }

    companion object {
        fun connect(
            tunnelInput: InputStream,
            tunnelOutput: OutputStream,
            parameters: TunnelParameters,
            handshake: Rsd.Handshake,
        ): DvtClient {
            val service = handshake.service(ProcessControl.SERVICE)
                ?: handshake.services.firstOrNull { it.name.contains("processcontrol", ignoreCase = true) }
                ?: throw DvtException(
                    "ProcessControl not in RSD services: ${handshake.services.map { it.name }}",
                )
            val tcp = UserspaceTcp.connect(tunnelInput, tunnelOutput, parameters, service.port)
            return DvtClient(tcp.input, tcp.output, tcp)
        }
    }
}
