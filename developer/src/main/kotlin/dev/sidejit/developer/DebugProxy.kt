package dev.sidejit.developer

/**
 * debugproxy / DVT ProcessControl surface.
 * Requires a live RSD endpoint; not implemented until CoreDevice + RSD land.
 */
object DebugProxy {
    class NotImplemented(message: String = "debugproxy is not implemented yet") : Exception(message)

    fun attachForJit(bundleId: String, pid: Long): Nothing =
        throw NotImplemented("attachForJit($bundleId, $pid): needs DVT + debugproxy channel")
}
