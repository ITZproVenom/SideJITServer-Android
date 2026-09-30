package dev.sidejit.jit

import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.developer.DebugAttach
import dev.sidejit.developer.GdbConnection
import java.io.InputStream
import java.io.OutputStream

/** Finds the pid of a running app on the iOS device. */
fun interface ProcessResolver {
    /** Returns the pid, or throws [JitException] naming why it could not. */
    fun pidFor(bundleId: String): Int
}

/** An open socket to the device's debugserver. */
interface DebugChannel : AutoCloseable {
    val input: InputStream
    val output: OutputStream
}

/** Opens a debugserver socket through the tunnel. */
fun interface DebugServerConnector {
    fun open(): DebugChannel
}

/** A named stage failed. [stage] is one of the log tags so the screen can point at it. */
class JitException(val stage: String, message: String, cause: Throwable? = null) : Exception(message, cause)

sealed interface JitResult {
    data class Granted(val bundleId: String, val pid: Int) : JitResult
    data class Failed(val bundleId: String, val stage: String, val reason: String) : JitResult
}

/**
 * bundle identifier -> pid -> debugserver -> attach -> detach.
 *
 * Every failure is returned with the stage it happened in. Nothing here
 * reports success unless the debug server confirmed the attach and the detach.
 */
class JitOrchestrator(
    private val resolver: ProcessResolver,
    private val connector: DebugServerConnector,
) {
    fun enable(bundleId: String): JitResult {
        if (bundleId.isBlank() || bundleId.length > 255 || bundleId.any { it.isWhitespace() }) {
            return JitResult.Failed(bundleId.take(64), "JIT", "not a valid bundle identifier")
        }
        val pid = try {
            resolver.pidFor(bundleId)
        } catch (e: JitException) {
            Log.w(LogTag.JIT, "could not resolve $bundleId: ${e.message}")
            return JitResult.Failed(bundleId, e.stage, e.message ?: "unknown")
        }
        return try {
            connector.open().use { channel ->
                val outcome = DebugAttach(GdbConnection(channel.input, channel.output)).attachAndDetach(pid)
                Log.i(LogTag.JIT, "JIT granted to $bundleId (pid ${outcome.pid})")
                JitResult.Granted(bundleId, outcome.pid)
            }
        } catch (e: JitException) {
            JitResult.Failed(bundleId, e.stage, e.message ?: "unknown")
        } catch (e: Exception) {
            Log.e(LogTag.JIT, "attach failed for $bundleId", e)
            JitResult.Failed(bundleId, "GDB", e.message ?: e.javaClass.simpleName)
        }
    }
}

/** Used until the DVT layer exists. It fails loudly instead of guessing. */
object UnavailableProcessResolver : ProcessResolver {
    override fun pidFor(bundleId: String): Int =
        throw JitException("DVT", "process lookup needs the DVT/ProcessControl layer, which is not implemented yet")
}

/** Used until the tunnel exists. */
object UnavailableConnector : DebugServerConnector {
    override fun open(): DebugChannel =
        throw JitException("TUNNEL", "there is no tunnel to the device yet, so no debugserver connection can be opened")
}
