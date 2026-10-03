package dev.sidejit.pairing

import dev.sidejit.core.crypto.Ed25519
import dev.sidejit.core.crypto.SipHash
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdvertisementMatchTest {

    private fun record(altIrk: ByteArray, identifier: String = UUID.randomUUID().toString()) =
        PairingRecord(
            peer = PeerDevice(
                accountId = identifier,
                alternateIdentityKey = altIrk,
                model = "iPhone17,1",
                name = "Bestin's iPhone",
                udid = "UDID-$identifier",
                identifier = identifier,
                longTermPublicKey = Ed25519.generate().publicKey,
            ),
            sessionKey = ByteArray(64),
            establishedAtEpochSeconds = 1_700_000_000,
        )

    @Test
    fun `resolves an advertisement whose authTag was made with the stored key`() {
        val altIrk = ByteArray(16) { (it + 1).toByte() }
        val stored = record(altIrk)
        val instance = "4A1B2C3D-0000-1111-2222-333344445555"
        val txt = mapOf(
            "authTag" to SipHash.authTagBase64(altIrk, instance),
            "name" to "iPhone",
        )
        assertTrue(AdvertisementMatch.matches(stored, instance, txt))
        assertEquals(stored, AdvertisementMatch.firstMatch(listOf(record(ByteArray(16)), stored), instance, txt))
    }

    @Test
    fun `rejects an advertisement for another device`() {
        val stored = record(ByteArray(16) { (it + 1).toByte() })
        val instance = "4A1B2C3D-0000-1111-2222-333344445555"
        val txt = mapOf("authTag" to SipHash.authTagBase64(ByteArray(16) { (it + 9).toByte() }, instance))
        assertFalse(AdvertisementMatch.matches(stored, instance, txt))
        assertNull(AdvertisementMatch.firstMatch(listOf(stored), instance, txt))
    }

    @Test
    fun `the tag is bound to the instance name`() {
        val altIrk = ByteArray(16) { (it + 1).toByte() }
        val stored = record(altIrk)
        val txt = mapOf("authTag" to SipHash.authTagBase64(altIrk, "one-name"))
        assertFalse(AdvertisementMatch.matches(stored, "another-name", txt))
    }

    @Test
    fun `falls back to a plainly advertised identifier`() {
        val stored = record(ByteArray(16) { (it + 1).toByte() })
        assertTrue(
            AdvertisementMatch.matches(
                stored,
                "whatever",
                mapOf("identifier" to stored.peer.identifier.lowercase()),
            ),
        )
        assertTrue(AdvertisementMatch.matches(stored, "whatever", mapOf("udid" to stored.peer.udid)))
    }

    @Test
    fun `an advertisement with nothing usable never matches`() {
        val stored = record(ByteArray(16) { (it + 1).toByte() })
        assertFalse(AdvertisementMatch.matches(stored, "whatever", emptyMap()))
        assertFalse(AdvertisementMatch.matches(stored, "whatever", mapOf("authTag" to "")))
        assertFalse(AdvertisementMatch.matches(stored, "whatever", mapOf("model" to "iPhone17,1")))
    }
}
