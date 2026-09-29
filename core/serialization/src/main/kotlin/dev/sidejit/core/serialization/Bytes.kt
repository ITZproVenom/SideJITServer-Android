package dev.sidejit.core.serialization

/** Hex, for logs and test vectors. Never for secrets: the log redacts those. */
fun ByteArray.toHex(): String {
    val out = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        out.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
    }
    return out.toString()
}

private const val HEX = "0123456789abcdef"

fun String.hexToBytes(): ByteArray {
    val clean = filterNot { it.isWhitespace() || it == ':' }
    require(clean.length % 2 == 0) { "hex string has an odd number of digits" }
    val out = ByteArray(clean.length / 2)
    for (i in out.indices) {
        out[i] = ((digit(clean[i * 2]) shl 4) or digit(clean[i * 2 + 1])).toByte()
    }
    return out
}

private fun digit(c: Char): Int {
    val value = Character.digit(c, 16)
    require(value >= 0) { "'$c' is not a hex digit" }
    return value
}

/**
 * Compares two arrays without letting the time taken reveal where they first
 * differ. Used for every authentication tag and proof value.
 */
fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var difference = 0
    for (i in a.indices) difference = difference or (a[i].toInt() xor b[i].toInt())
    return difference == 0
}

fun ByteArray.concat(vararg others: ByteArray): ByteArray {
    var total = size
    for (o in others) total += o.size
    val out = ByteArray(total)
    System.arraycopy(this, 0, out, 0, size)
    var offset = size
    for (o in others) {
        System.arraycopy(o, 0, out, offset, o.size)
        offset += o.size
    }
    return out
}
