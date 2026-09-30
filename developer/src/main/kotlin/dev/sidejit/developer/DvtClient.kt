package dev.sidejit.developer

import dev.sidejit.coredevice.Http2
import dev.sidejit.coredevice.RemoteXpc
import dev.sidejit.coredevice.Rsd
import dev.sidejit.coredevice.TunnelParameters
import dev.sidejit.coredevice.UserspaceTcp
import java.io.InputStream
import java.io.OutputStream

class DvtClient(private val input: InputStream, private val output: OutputStream) {
    class DvtException(message: String, cause: Throwable? = null) : Exception(message, cause)

    fun openChannel() {
        RemoteXpc.writePreface(output)
        try { if (input.available() > 0) Http2.readFrame(input) } catch (_: Exception) {}
    }

    fun sendArchive(payload: ByteArray, streamId: Int = 1) {
        output.write(Http2.encodeFrame(Http2.FRAME_DATA, Http2.FLAG_END_STREAM, streamId, payload))
        output.flush()
    }

    fun launchSuspended(bundleId: String) {
        openChannel()
        sendArchive(ProcessControl.launchSuspendedArchive(bundleId))
    }

    companion object {
        fun connect(
            tunnelInput: InputStream, tunnelOutput: OutputStream,
            parameters: TunnelParameters, handshake: Rsd.Handshake,
        ): DvtClient {
            val service = handshake.service(ProcessControl.SERVICE)
                ?: handshake.services.firstOrNull { it.name.contains("processcontrol", ignoreCase = true) }
                ?: throw DvtException("ProcessControl not in RSD services: ${handshake.services.map { it.name }}")
            val tcp = UserspaceTcp.connect(tunnelInput, tunnelOutput, parameters, service.port)
            return DvtClient(tcp.input, tcp.output)
        }
    }
}
