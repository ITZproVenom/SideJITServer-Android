package dev.sidejit.pairing

import dev.sidejit.core.crypto.SipHash
import java.util.Base64

/**
 * Decides whether a `_remotepairing._tcp` advertisement belongs to a device we already paired
 * with.
 *
 * The advertisement never carries the device identifier in the clear. It carries an `authTag`,
 * a SipHash-2-4 of the service instance name under the alternate identity resolving key that
 * was exchanged during pair setup. Only a host holding that key can recognise the device, which
 * is the whole point: the tag changes with the instance name so the device is not trackable.
 */
object AdvertisementMatch {

    /** TXT keys that have been observed to carry the identity tag. */
    private val TAG_KEYS = listOf("authTag", "authtag", "auth-tag")

    /** TXT keys that sometimes carry a plain identifier instead of a tag. */
    private val IDENTIFIER_KEYS = listOf("identifier", "id", "udid", "remotepairing_udid")

    /**
     * True when [txtRecords] advertised under [instanceName] resolves to [record].
     *
     * The comparison is constant time so a hostile responder on the same link cannot learn the
     * key by timing our replies.
     */
    fun matches(record: PairingRecord, instanceName: String, txtRecords: Map<String, String>): Boolean {
        val key = record.peer.alternateIdentityKey
        if (key.isNotEmpty()) {
            val expected = SipHash.authTagBase64(key, instanceName)
            for (candidate in tagValues(txtRecords)) {
                if (constantTimeEquals(candidate, expected)) return true
                // Some responders publish the raw tag rather than base64 of it.
                if (constantTimeEquals(normalizeBase64(candidate), expected)) return true
            }
        }
        for (candidate in identifierValues(txtRecords)) {
            if (candidate.equals(record.peer.identifier, ignoreCase = true)) return true
            if (candidate.equals(record.peer.udid, ignoreCase = true)) return true
        }
        return false
    }

    /** The first stored record that the advertisement resolves to, or null. */
    fun firstMatch(
        records: List<PairingRecord>,
        instanceName: String,
        txtRecords: Map<String, String>,
    ): PairingRecord? = records.firstOrNull { matches(it, instanceName, txtRecords) }

    private fun tagValues(txtRecords: Map<String, String>): List<String> {
        val found = ArrayList<String>()
        for ((key, value) in txtRecords) {
            if (value.isEmpty()) continue
            if (TAG_KEYS.any { it.equals(key, ignoreCase = true) }) found.add(value)
        }
        return found
    }

    private fun identifierValues(txtRecords: Map<String, String>): List<String> {
        val found = ArrayList<String>()
        for ((key, value) in txtRecords) {
            if (value.isEmpty()) continue
            if (IDENTIFIER_KEYS.any { it.equals(key, ignoreCase = true) }) found.add(value)
        }
        return found
    }

    /** Re-encodes a tag that arrived in some other encoding so it can be compared. */
    private fun normalizeBase64(value: String): String =
        try {
            Base64.getEncoder().encodeToString(Base64.getUrlDecoder().decode(value))
        } catch (_: IllegalArgumentException) {
            value
        }

    private fun constantTimeEquals(left: String, right: String): Boolean {
        val a = left.toByteArray(Charsets.UTF_8)
        val b = right.toByteArray(Charsets.UTF_8)
        if (a.isEmpty() || b.isEmpty()) return false
        var difference = a.size xor b.size
        for (index in a.indices) {
            difference = difference or (a[index].toInt() xor b[index % b.size].toInt())
        }
        return difference == 0
    }
}
