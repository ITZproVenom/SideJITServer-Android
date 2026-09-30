package dev.sidejit.coredevice

/** Remote Service Discovery over the CoreDevice tunnel. Not implemented. */
object Rsd {
    class NotImplemented(message: String = "RSD is not implemented yet") : Exception(message)

    fun discover(): Nothing = throw NotImplemented()
}
