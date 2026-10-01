package dev.sidejit.jit

import dev.sidejit.coredevice.CoreDeviceTunnel
import dev.sidejit.coredevice.RsdClient
import dev.sidejit.coredevice.UserspaceTcp
import dev.sidejit.developer.DebugProxy
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

    /**
     * Full software path when pair-verify + createListener port are already known.
     * Never claims Granted unless GDB sequence completes on an open debugproxy stream
     * (which still requires a live device to produce a real PID and service).
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

                    val pc = handshake.service(ProcessControl.SERVICE)
                        ?: handshake.services.firstOrNull {
                            it.name.contains("processcontrol", ignoreCase = true)
                        }
                    if (pc == null) {
                        return Result.Failed(
                            "userspace TCP + RSD ok; ProcessControl not advertised " +
                                "(services=$serviceNames); bundleId=$bundleId",
                        )
                    }

                    val processTcp = UserspaceTcp.connect(
                        tunnel.input,
                        tunnel.output,
                        tunnel.parameters,
                        pc.port,
                    )
                    try {
                        DtxProcessControl(processTcp.input, processTcp.output).use { processControl ->
                            val pid = processControl.launchSuspended(bundleId)

                            // Connect to the modern RSD debugproxy service and perform
                            // the synchronous GDB attach/detach sequence.
                            val debugSvc = handshake.service(ProcessControl.DEBUGPROXY)
                                ?: handshake.service(ProcessControl.DEBUGSERVER)
                                ?: handshake.services.firstOrNull {
                                    it.name.contains("debugproxy", ignoreCase = true)
                                }
                            if (debugSvc == null) {
                                return Result.Failed(
                                    "ProcessControl launched pid=$pid for $bundleId but no " +
                                        "debugproxy service is advertised (services=$serviceNames)",
                                )
                            }

                            val debugTcp = UserspaceTcp.connect(
                                tunnel.input,
                                tunnel.output,
                                tunnel.parameters,
                                debugSvc.port,
                            )
                            try {
                                DebugProxy.attachForJit(debugTcp.input, debugTcp.output, pid)
                                Result.Granted(bundleId, pid)
                            } catch (gdbFail: Exception) {
                                Result.Failed(
                                    "pid=$pid for $bundleId; debugproxy open ok on port " +
                                        debugSvc.port + " but GDB sequence failed: " + gdbFail.message,
                                )
                            } finally {
                                runCatching { debugTcp.close() }
                            }
                        }
                    } finally {
                        runCatching { processTcp.close() }
                    }
                        val debugSvc = handshake.service(ProcessControl.DEBUGPROXY)
                            ?: handshake.service(ProcessControl.DEBUGSERVER)
                            ?: handshake.services.firstOrNull {
                                it.name.contains("debugserver", ignoreCase = true) ||
                                    it.name.contains("debugproxy", ignoreCase = true)
                            }
                        if (debugSvc == null) {
                            return Result.Failed(
                                "DVT returned pid=$pid for $bundleId but no debugproxy/debugserver " +
                                    "in RSD (services=$serviceNames)",
                            )
                        }

                        val debugTcp = UserspaceTcp.connect(
                            tunnel.input,
                            tunnel.output,
                            tunnel.parameters,
                            debugSvc.port,
                        )
                        try {
                            DebugProxy.attachForJit(debugTcp.input, debugTcp.output, pid)
                            // GDB sequence was written; without a live device we cannot
                            // confirm the kernel granted JIT. Report success only if the
                            // stream path completed without exception — still document
                            // that physical validation is required.
                            Result.Granted(bundleId, pid)
                        } catch (gdbFail: Exception) {
                            Result.Failed(
                                "pid=$pid for $bundleId; debugproxy open ok on port " +
                                    "${debugSvc.port} but GDB sequence failed: ${gdbFail.message}",
                            )
                        } finally {
                            runCatching { debugTcp.close() }
                        }
                    }
                } finally {
                    runCatching { rsdTcp.close() }
                }
            }
        } catch (failure: Exception) {
            Result.Failed("path failed: ${failure.message}")
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
        appendLine("RSD parse + client: code present")
        appendLine("RemoteXPC HTTP/2 frames: code present")
        appendLine("NSKeyedArchive encoder (DVT method calls): code present")
        appendLine("ProcessControl launch archive: code present")
        appendLine("DTX ProcessControl + NSKeyedArchive launch: code present")
        appendLine("debugproxy + GDB attach sequence: code present")
        appendLine("live device validation: none")
    }
}
