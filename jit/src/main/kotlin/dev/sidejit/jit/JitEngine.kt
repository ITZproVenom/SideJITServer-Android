package dev.sidejit.jit

import dev.sidejit.coredevice.CoreDeviceTunnel
import dev.sidejit.coredevice.RsdClient
import dev.sidejit.coredevice.UserspaceTcp
import dev.sidejit.developer.DebugProxy
import dev.sidejit.developer.DtxProcessControl
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
            "JIT needs a live device path: pair-verify -> createListener -> " +
                "CoreDeviceTunnel.openDataPlane -> UserspaceTcp -> RSD -> DTX ProcessControl -> " +
                "debugproxy -> GDB attach. bundleId=$bundleId",
        )

    /**
     * Full software path when pair-verify and createListener port are already known.
     * A Result.Granted only means the complete software sequence returned without
     * protocol error. Physical iPhone/iPad validation is still required.
     */
    fun enable(
        bundleId: String,
        session: VerifiedSession,
        deviceHost: String,
        listenerPort: Int,
    ): Result {
        return try {
            CoreDeviceTunnel.open(session, deviceHost, listenerPort).use { tunnel ->
                val rsdTcp = UserspaceTcp.connect(
                    tunnel.input,
                    tunnel.output,
                    tunnel.parameters,
                    tunnel.parameters.serverRsdPort,
                )
                try {
                    val handshake = RsdClient(rsdTcp.input, rsdTcp.output).readHandshake()
                    val serviceNames = handshake.services.map { it.name }

                    val processService = handshake.service(ProcessControl.SERVICE)
                        ?: handshake.services.firstOrNull {
                            it.name.contains("processcontrol", ignoreCase = true)
                        }
                        ?: return Result.Failed(
                            "RSD did not advertise ProcessControl (services=$serviceNames); " +
                                "bundleId=$bundleId",
                        )

                    val processTcp = UserspaceTcp.connect(
                        tunnel.input,
                        tunnel.output,
                        tunnel.parameters,
                        processService.port,
                    )
                    try {
                        val pid = DtxProcessControl(
                            processTcp.input,
                            processTcp.output,
                        ).use { processControl ->
                            processControl.launchSuspended(bundleId)
                        }

                        val debugService = handshake.service(ProcessControl.DEBUGPROXY)
                            ?: handshake.service(ProcessControl.DEBUGSERVER)
                            ?: handshake.services.firstOrNull {
                                it.name.contains("debugproxy", ignoreCase = true) ||
                                    it.name.contains("debugserver", ignoreCase = true)
                            }
                            ?: return Result.Failed(
                                "ProcessControl launched pid=$pid for $bundleId but RSD " +
                                    "did not advertise a debugproxy/debugserver service " +
                                    "(services=$serviceNames)",
                            )

                        val debugTcp = UserspaceTcp.connect(
                            tunnel.input,
                            tunnel.output,
                            tunnel.parameters,
                            debugService.port,
                        )
                        try {
                            DebugProxy.attachForJit(debugTcp.input, debugTcp.output, pid)
                            return Result.Granted(bundleId, pid)
                        } catch (failure: Exception) {
                            return Result.Failed(
                                "pid=$pid for $bundleId; debugproxy/GDB failed: " + failure.message,
                            )
                        } finally {
                            runCatching { debugTcp.close() }
                        }
                    } finally {
                        runCatching { processTcp.close() }
                    }
                } finally {
                    runCatching { rsdTcp.close() }
                }
            }
        } catch (failure: Exception) {
            Result.Failed("path failed: " + (failure.message ?: failure.javaClass.simpleName))
        }
    }

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

    fun processControlLaunchArchive(bundleId: String): ByteArray =
        ProcessControl.launchSuspendedArchive(bundleId)

    fun gdbSequence(pid: Long): List<String> = GdbRemote.jitAttachSequence(pid)

    fun describeStack(): String = buildString {
        appendLine("pair-setup/verify: code present")
        appendLine("TLS-PSK + CDTunnel: code present")
        appendLine("userspace TCP (client, IPv6, raw-packet CDTunnel framing): code present")
        appendLine("RSD RemoteXPC XPC over HTTP/2: code present")
        appendLine("DTX ProcessControl + NSKeyedArchive launch: code present")
        appendLine("debugproxy + synchronized GDB attach/detach: code present")
        appendLine("live device validation: none")
    }
}
