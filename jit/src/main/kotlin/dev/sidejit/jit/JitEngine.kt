package dev.sidejit.jit

import dev.sidejit.coredevice.CoreDeviceTunnel
import dev.sidejit.coredevice.RsdCheckin
import dev.sidejit.coredevice.RsdClient
import dev.sidejit.coredevice.TunnelDiagnostics
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
     * Opens a tunnel of its own and runs the whole path.
     *
     * Prefer [enableOnTunnel] with a tunnel that is already up: iOS closes a listener created by
     * createListener if nothing connects to it promptly, so a port obtained earlier is usually
     * dead by the time a person taps a button.
     */
    fun enable(
        bundleId: String,
        session: VerifiedSession,
        deviceHost: String,
        listenerPort: Int,
    ): Result =
        try {
            CoreDeviceTunnel.open(session, deviceHost, listenerPort).use { tunnel ->
                enableOnTunnel(bundleId, tunnel)
            }
        } catch (failure: Exception) {
            Result.Failed("path failed: " + (failure.message ?: failure.javaClass.simpleName))
        }

    /**
     * Runs the developer-services path over a tunnel that is already open.
     *
     * A Granted only means the whole software sequence returned without protocol error.
     */
    fun enableOnTunnel(bundleId: String, tunnel: CoreDeviceTunnel.OpenedTunnel): Result {
        return try {
            val rsdTcp = UserspaceTcp.connect(
                tunnel.input,
                tunnel.output,
                tunnel.parameters,
                tunnel.parameters.serverRsdPort,
            )
            try {
                val handshake = RsdClient(rsdTcp.input, rsdTcp.output).readHandshake()
                val serviceNames = handshake.services.map { it.name }
                TunnelDiagnostics.record("RSD services: " + serviceNames.joinToString(", "))

                // DTX is reached through dtservicehub. The process control channel is asked
                // for over that connection; RSD does not advertise it by name.
                val processService = handshake.service(ProcessControl.DTSERVICEHUB)
                    ?: handshake.services.firstOrNull {
                        it.name.contains("dtservicehub", ignoreCase = true) ||
                            it.name.contains("processcontrol", ignoreCase = true)
                    }
                    ?: return Result.Failed(
                        "RSD did not advertise ${ProcessControl.DTSERVICEHUB} (services=$serviceNames); " +
                            "bundleId=$bundleId",
                    )

                val processTcp = UserspaceTcp.connect(
                    tunnel.input,
                    tunnel.output,
                    tunnel.parameters,
                    processService.port,
                )
                try {
                    if (!processService.usesRemoteXpc) {
                        RsdCheckin.perform(
                            processTcp.input,
                            processTcp.output,
                            processService.name,
                        )
                    }
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
                        if (!debugService.usesRemoteXpc) {
                            RsdCheckin.perform(
                                debugTcp.input,
                                debugTcp.output,
                                debugService.name,
                            )
                        }
                        DebugProxy.attachForJit(debugTcp.input, debugTcp.output, pid)
                        TunnelDiagnostics.record("debugproxy attached and detached for pid $pid")
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
