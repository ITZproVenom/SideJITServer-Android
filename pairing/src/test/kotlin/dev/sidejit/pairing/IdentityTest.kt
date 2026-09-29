package dev.sidejit.pairing

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HostIdentityTest {
    @Test
    fun `a generated identity round trips through its stored form`() {
        val original = HostIdentity.generate(name = "SideJIT on the living room TV")
        val restored = HostIdentity.decode(original.encode())
        assertEquals(original.identifier, restored.identifier)
        assertEquals(original.udid, restored.udid)
        assertEquals(original.name, restored.name)
        assertEquals(original.model, restored.model)
        assertArrayEquals(original.alternateIdentityKey, restored.alternateIdentityKey)
        assertArrayEquals(original.longTermPublicKey, restored.longTermPublicKey)
    }

    @Test
    fun `the mdns host name follows the pattern a device expects`() {
        val identity = HostIdentity.generate(name = "SideJIT")
        assertEquals("idevice-${identity.identifier.take(8).lowercase()}", identity.mdnsHostName)
        assertTrue(identity.mdnsHostName.length <= 17)
    }

    @Test
    fun `the txt records carry the fields a device looks for`() {
        val identity = HostIdentity.generate(name = "SideJIT")
        val txt = identity.mdnsTxtRecords(pinless = false)
        assertEquals(identity.name, txt["name"])
        assertEquals(identity.identifier, txt["identifier"])
        assertEquals(identity.model, txt["model"])
        assertEquals("1", txt["flags"])
        assertEquals("26", txt["ver"])
        assertEquals("17", txt["minVer"])
        assertEquals(6, Base64.getDecoder().decode(txt["authTag"]).size)
        assertNull(txt["pinless"])
        assertEquals("1", identity.mdnsTxtRecords(pinless = true)["pinless"])
    }

    @Test
    fun `two generated identities differ`() {
        val first = HostIdentity.generate(name = "a")
        val second = HostIdentity.generate(name = "b")
        assertTrue(first.identifier != second.identifier)
        assertTrue(!first.alternateIdentityKey.contentEquals(second.alternateIdentityKey))
        assertTrue(!first.longTermPublicKey.contentEquals(second.longTermPublicKey))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `an identity with the wrong key size is refused`() {
        HostIdentity("x", ByteArray(16), ByteArray(16), "y", "n", "m")
    }
}

class PairingRecordTest {
    private val peer = PeerDevice(
        accountId = "ACCOUNT",
        alternateIdentityKey = ByteArray(16) { it.toByte() },
        model = "iPhone17,1",
        name = "Test iPhone",
        udid = "UDID",
        identifier = "IDENTIFIER",
        longTermPublicKey = ByteArray(32) { (it * 3).toByte() },
    )

    @Test
    fun `a record round trips through its stored form`() {
        val record = PairingRecord(peer, ByteArray(64) { it.toByte() }, 1_700_000_000L)
        assertEquals(record, PairingRecord.decode(record.encode()))
    }

    @Test
    fun `the in memory store keeps one record per device`() {
        val store = InMemoryPairingStore()
        store.save(PairingRecord(peer, ByteArray(64), 1))
        store.save(PairingRecord(peer, ByteArray(64) { 1 }, 2))
        assertEquals(1, store.all().size)
        assertEquals(2L, store.load("IDENTIFIER")?.establishedAtEpochSeconds)
        store.delete("IDENTIFIER")
        assertTrue(store.all().isEmpty())
        assertNull(store.load("IDENTIFIER"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a peer with the wrong alternate key size is refused`() {
        peer.copy(alternateIdentityKey = ByteArray(8))
    }
}