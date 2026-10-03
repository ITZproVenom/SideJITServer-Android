package dev.sidejit.coredevice

import java.util.ArrayDeque

/**
 * A small ring buffer of what happened on the tunnel.
 *
 * The device is not in front of whoever is reading the code, and an Android TV has no usable
 * log view, so the last few hundred events are kept in memory and served over the HTTP API.
 * Nothing secret goes in here: addresses, ports, flags and sizes only.
 */
object TunnelDiagnostics {
    private const val CAPACITY = 300

    private val events = ArrayDeque<String>(CAPACITY)
    private val lock = Any()

    @Volatile
    private var startedAt = 0L

    fun record(event: String) {
        synchronized(lock) {
            if (startedAt == 0L) startedAt = System.currentTimeMillis()
            if (events.size >= CAPACITY) events.removeFirst()
            events.addLast("+${System.currentTimeMillis() - startedAt}ms $event")
        }
    }

    fun reset() {
        synchronized(lock) {
            events.clear()
            startedAt = 0L
        }
    }

    fun snapshot(): List<String> = synchronized(lock) { events.toList() }

    /** A readable hex form of an IPv6 address for the log. */
    fun address(bytes: ByteArray): String =
        if (bytes.size != 16) {
            "?"
        } else {
            (0 until 8).joinToString(":") { index ->
                val value = ((bytes[index * 2].toInt() and 0xFF) shl 8) or
                    (bytes[index * 2 + 1].toInt() and 0xFF)
                value.toString(16)
            }
        }

    fun flags(value: Int): String = buildString {
        if (value and 0x02 != 0) append("SYN ")
        if (value and 0x10 != 0) append("ACK ")
        if (value and 0x01 != 0) append("FIN ")
        if (value and 0x04 != 0) append("RST ")
        if (value and 0x08 != 0) append("PSH ")
        if (isEmpty()) append("none")
    }.trim()
}
