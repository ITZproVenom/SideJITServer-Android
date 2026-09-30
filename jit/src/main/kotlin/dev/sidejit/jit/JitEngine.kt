package dev.sidejit.jit

/**
 * Orchestration entry point for "grant JIT to this bundle id".
 *
 * The sequence will be: ensure pairing -> tunnel -> RSD -> ProcessControl launch
 * suspended -> GdbRemote attach/detach. Until the tunnel exists this always fails
 * with a clear reason; it never pretends success.
 */
object JitEngine {
    sealed class Result {
        data class Granted(val bundleId: String, val pid: Long) : Result()
        data class Failed(val reason: String) : Result()
    }

    fun enable(bundleId: String): Result =
        Result.Failed(
            "JIT is not implemented yet: CoreDevice tunnel, RSD, DVT and debugproxy " +
                "are still missing. Pairing setup/verify and GDB packet codec exist in isolation. " +
                "Requested bundleId=$bundleId",
        )
}
