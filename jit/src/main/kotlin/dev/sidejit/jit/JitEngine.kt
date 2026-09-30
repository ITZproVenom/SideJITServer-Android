package dev.sidejit.jit

import dev.sidejit.coredevice.CoreDeviceTunnel
import dev.sidejit.coredevice.RsdClient
import dev.sidejit.coredevice.UserspaceTcp
import dev.sidejit.developer.DebugProxy
import dev.sidejit.developer.DvtClient
import dev.sidejit.developer.GdbRemote
import dev.sidejit.developer.ProcessControl
import dev.sidejit.pairing.VerifiedSession
import java.io.InputStream
import java.io.OutputStream

object JitEngine {
    sealed class Result {
        data class Granted(val bundleId: String, val pid: Long) : Result()
        data class Failed(val reason: String) : Result()
    }

    fun enable(bundleId: String): Result =
        Result.Failed(
            "JIT needs a live device path: pair-verify → createListener → " +
                "CoreDeviceTunnel.openDataPlane → UserspaceTcp → RSD → DVT/ProcessControl → " +
                "debugproxy → GDB attach. bundleId=$bundleId",
        )

    fun enable(bundleId: String, session: VerifiedSession, deviceHost: String, listenerPort: Int): Result {
        return try {
            CoreDeviceTunnel.open(session, deviceHost, listenerPort).use { tunnel ->
                val rsdTcp = UserspaceTcp.connect(tunnel.input, tunnel.output, tunnel.parameters, tunnel.parameters.serverRsdPort)
                try {
                    val handshake = RsdClient(rsdTcp.input, rsdTcp.output).readHandshake()
                    val pc = handshake.service(ProcessControl.SERVICE)
                        ?: handshake.services.firstOrNull { it.name.contains("processcontrol", ignoreCase = true) }
                    if (pc != null) {
                        try {
                            val dvt = DvtClient.connect(tunnel.input, tunnel.output, tunnel.parameters, handshake)
                            dvt.launchSuspended(bundleId)
                            return Result.Failed(
                                "DVT launchSuspended archive sent for $bundleId; " +
                                    "live PID reply + debugproxy GDB attach require device " +
                                    "(RSD services=${handshake.services.map { it.name }})",
                            )
                        } catch (dvtFailure: Exception) {
                            return Result.Failed(
                                "RSD ok services=${handshake.services.map { it.name }}; DVT path failed: ${dvtFailure.message}",
                            )
                        }
                    }
                    Result.Failed(
                        "userspace TCP + RSD handshake ok; ProcessControl not advertised " +
                            "(services=${handshake.services.map { it.name }}); bundleId=$bundleId",
                    )
                } finally { runCatching { rsdTcp.close() } }
            }
        } catch (failure: Exception) {
            Result.Failed("path failed: ${failure.message}")
        }
    }

    fun enableOnStreams(bundleId: String, pid: Long, input: InputStream, output: OutputStream): Result {
        return try {
            DebugProxy.attachForJit(input, output, pid)
            Result.Granted(bundleId, pid)
        } catch (failure: Exception) {
            Result.Failed("GDB attach failed: ${failure.message}")
        }
    }

    fun processControlLaunchPayload(bundleId: String) = ProcessControl.launchSuspended(bundleId)
    fun processControlLaunchArchive(bundleId: String): ByteArray = ProcessControl.launchSuspendedArchive(bundleId)
    fun gdbSequence(pid: Long): List<String> = GdbRemote.jitAttachSequence(pid)

    fun describeStack(): String = buildString {
        appendLine("pair-setup/verify: code present")
        appendLine("TLS-PSK + CDTunnel: code present")
        appendLine("userspace TCP (client, IPv6, length-prefixed): code present")
        appendLine("RSD parse + client: code present")
        appendLine("RemoteXPC HTTP/2 frames: code present")
        appendLine("NSKeyedArchive encoder (DVT method calls): code present")
        appendLine("ProcessControl launch archive: code present")
        appendLine("DvtClient (RemoteXPC + archive send): code present")
        appendLine("GDB attach sequence: code present")
        appendLine("live device validation: none")
    }
}
