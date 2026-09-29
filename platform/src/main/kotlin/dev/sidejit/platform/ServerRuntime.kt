package dev.sidejit.platform

import android.content.Context
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The server, independent of anything on screen.
 *
 * The television this is meant to run on may have no working display at all,
 * so nothing here may depend on an Activity existing, being visible, or ever
 * having been visible. The foreground service owns this object; the interface
 * only reads [state].
 */
class ServerRuntime private constructor(private val context: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val started = AtomicBoolean(false)

    private val _state = MutableStateFlow(ServerState())
    val state: StateFlow<ServerState> = _state.asStateFlow()

    fun start() {
        if (!started.compareAndSet(false, true)) return
        Log.i(LogTag.SERVER, "runtime starting")
        _state.update { it.copy(wifi = Stage("Wi-Fi", StageStatus.RUNNING, "looking for an address")) }
        // Subsequent phases attach here as they land. Nothing is reported as
        // ready before the code behind it exists.
    }

    fun stop() {
        if (!started.compareAndSet(true, false)) return
        Log.i(LogTag.SERVER, "runtime stopping")
        _state.value = ServerState()
    }

    internal fun update(transform: (ServerState) -> ServerState) = _state.update(transform)

    companion object {
        @Volatile
        private var instance: ServerRuntime? = null

        fun get(context: Context): ServerRuntime =
            instance ?: synchronized(this) {
                instance ?: ServerRuntime(context.applicationContext).also { instance = it }
            }
    }
}
