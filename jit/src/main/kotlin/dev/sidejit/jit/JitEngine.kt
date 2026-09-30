package dev.sidejit.jit

import dev.sidejit.coredevice.CoreDeviceTunnel
import dev.sidejit.coredevice.Rsd
import dev.sidejit.developer.DebugProxy
import dev.sidejit.developer.GdbRemote
import dev.sidejit.developer.ProcessControl
import dev.sidejit.pairing.VerifiedSession
import java.io.InputStream
import java.io.OutputStream

/**
 * Orchestrates: verified pairing → tunnel data plane → RSD → ProcessControl → GDB attach.
 *
 * [enable] without a live device returns [Result.Failed] with the missing step named.
 * [enableOnStreams] runs GDB against already-open debugproxy streams (for tests / partial integration).
 */
object JitEngine {
    sealed class Result {
        data class Granted(val bundleId: String, val pid: Long) : Result()
        data class Failed(val reason: String) : Result()
    }

    fun enable(bundleId: String): Result =
        Result.Failed(
            "JIT needs a live device path: pair-verify → createListener → " +
                "CoreDeviceTunnel.openDataPlane → RSD → ProcessControl.launchSuspended → " +
                "DebugProxy.attachForJit. bundleId=$bundleId",
        )

    fun enable(
        bundleId: String,
        session: VerifiedSession,
        deviceHost: String,
        listenerPort: Int,
    ): Result {
        return try {
            CoreDeviceTunnel.open(session, deviceHost, listenerPort).use { tunnel ->
                Result.Failed(
                    "tunnel opened to ${tunnel.parameters.serverAddress}:${tunnel.parameters.serverRsdPort}; " +
                        "userspace TCP to RSD and DVT are next (bundleId=$bundleId)",
                )
            }
        } catch (failure: Exception) {
            Result.Failed("tunnel failed: ${failure.message}")
        }
    }

    /** Runs only the GDB half when debugproxy streams are already open. */
    fun enableOnStreams(
        bundleId: String,
        pid: Long,
        input: InputStream,
        output: OutputStream,
    ): Result {
        return try {
            DebugProxy.attachForJit(input, output, pid)
            Result.Granted(bundleId, pid)
        } catch (failure: Exception) {
            Result.Failed("GDB attach failed: ${failure.message}")
        }
    }

    fun processControlLaunchPayload(bundleId: String) = ProcessControl.launchSuspended(bundleId)

    fun gdbSequence(pid: Long): List<String> = GdbRemote.jitAttachSequence(pid)

    fun describeStack(): String = buildString {
        appendLine("pair-setup/verify: code present")
        appendLine("TLS-PSK + CDTunnel: code present")
        appendLine("RSD parse: code present")
        appendLine("RemoteXPC HTTP/2 frames: code present")
        appendLine("ProcessControl payloads: code present")
        appendLine("GDB attach sequence: code present")
        appendLine("userspace TCP to tunnel IPv6: partial")
        appendLine("live device validation: none")
    }
}
