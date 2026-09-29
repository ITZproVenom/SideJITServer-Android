package dev.sidejit.core.logging

/**
 * Where a line came from.
 *
 * The tags are fixed rather than free text so a log can be filtered by
 * protocol layer, which is the only way a stack this deep can be read: a
 * failure in `[GDB]` and a failure in `[TUNNEL]` look identical from the
 * outside and have nothing to do with each other.
 */
enum class LogTag(val label: String) {
    NETWORK("NETWORK"),
    MDNS("MDNS"),
    PAIRING("PAIRING"),
    TUNNEL("TUNNEL"),
    RSD("RSD"),
    XPC("XPC"),
    DVT("DVT"),
    DEBUGPROXY("DEBUGPROXY"),
    GDB("GDB"),
    JIT("JIT"),
    API("API"),
    SERVER("SERVER"),
    CRYPTO("CRYPTO"),
}

enum class LogLevel { DEBUG, INFO, WARN, ERROR }

data class LogLine(
    val millis: Long,
    val level: LogLevel,
    val tag: LogTag,
    val message: String,
) {
    override fun toString(): String = "[${tag.label}] ${level.name.first()} $message"
}

/** Somewhere for lines to go once they have been written. */
fun interface LogSink {
    fun write(line: LogLine)
}

/**
 * The application log.
 *
 * Every line is passed through [Redaction] on the way in. Doing it here rather
 * than at each call site is deliberate: this project handles pairing secrets,
 * long-term private keys and a setup PIN, and the one thing that must never
 * happen is any of them reaching a log the user is encouraged to share.
 */
object Log {
    private val sinks = mutableListOf<LogSink>()
    private val ring = ArrayDeque<LogLine>()
    private const val RING_CAPACITY = 1000

    @Volatile
    var minimumLevel: LogLevel = LogLevel.DEBUG

    @Synchronized
    fun addSink(sink: LogSink) {
        sinks += sink
    }

    @Synchronized
    fun removeSink(sink: LogSink) {
        sinks -= sink
    }

    /** The most recent lines, oldest first, safe to show or share. */
    @Synchronized
    fun recent(limit: Int = RING_CAPACITY): List<LogLine> =
        ring.toList().takeLast(limit)

    @Synchronized
    fun clear() = ring.clear()

    fun d(tag: LogTag, message: String) = write(LogLevel.DEBUG, tag, message)
    fun i(tag: LogTag, message: String) = write(LogLevel.INFO, tag, message)
    fun w(tag: LogTag, message: String) = write(LogLevel.WARN, tag, message)
    fun e(tag: LogTag, message: String) = write(LogLevel.ERROR, tag, message)

    fun e(tag: LogTag, message: String, error: Throwable) =
        write(LogLevel.ERROR, tag, "$message: ${error.describe()}")

    private fun write(level: LogLevel, tag: LogTag, message: String) {
        if (level.ordinal < minimumLevel.ordinal) return
        val line = LogLine(
            millis = System.currentTimeMillis(),
            level = level,
            tag = tag,
            message = Redaction.apply(message),
        )
        val copy: List<LogSink>
        synchronized(this) {
            ring.addLast(line)
            while (ring.size > RING_CAPACITY) ring.removeFirst()
            copy = sinks.toList()
        }
        copy.forEach { runCatching { it.write(line) } }
    }
}

/**
 * A throwable as one line.
 *
 * `toString` on an exception with a null message prints only the class name,
 * which in a protocol stack means a log that says `IOException` and nothing
 * else. The cause chain is usually where the real reason is.
 */
fun Throwable.describe(): String {
    val parts = mutableListOf<String>()
    var current: Throwable? = this
    var depth = 0
    while (current != null && depth < 5) {
        val text = current.message?.takeIf { it.isNotBlank() }
        parts += if (text != null) "${current::class.java.simpleName}: $text"
        else current::class.java.simpleName
        current = current.cause?.takeIf { it !== current }
        depth++
    }
    return parts.joinToString(" <- ")
}
