package dev.sidejit.core.logging

/**
 * Removes anything secret-shaped from text on its way into the log.
 *
 * The rules are blunt on purpose. A false positive costs a moment's confusion
 * while reading a log; a leaked pairing key costs the ability to impersonate
 * this host to the user's iPhone for as long as the pairing lives.
 */
object Redaction {
    private val rules: List<Pair<Regex, String>> = listOf(
        // A named secret and whatever follows it, in either JSON-ish or
        // Kotlin `field=value` shape.
        Regex(
            "(?i)((?:priv(?:ate)?|secret|seed|psk|srp|setup|pin|passcode|password|" +
                "token|ltsk|ltpk|irk|altirk|sharedkey|sessionkey|masterkey|salt|proof)" +
                "[a-z0-9_]*\\s*[=:]\\s*)[^\\s,;}\\)\\]]+"
        ) to "$1<redacted>",
        // A PEM block.
        Regex("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----")
            to "<redacted key>",
        // Long runs of hex or base64: key material, pairing blobs, SRP values.
        Regex("\\b[0-9a-fA-F]{48,}\\b") to "<redacted>",
        Regex("\\b[A-Za-z0-9+/_-]{56,}={0,2}\\b") to "<redacted>",
        // A bare six-digit setup code.
        Regex("(?<![0-9])[0-9]{6}(?![0-9])") to "<pin>",
    )

    fun apply(text: String): String {
        if (text.isEmpty()) return text
        var result = text
        for ((pattern, replacement) in rules) {
            result = pattern.replace(result, replacement)
        }
        return result
    }
}
