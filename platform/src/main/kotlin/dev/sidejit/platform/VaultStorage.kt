package dev.sidejit.platform

import android.content.Context
import android.os.Build
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag
import dev.sidejit.core.logging.describe
import dev.sidejit.pairing.HostIdentity
import dev.sidejit.pairing.PairingRecord
import dev.sidejit.pairing.PairingStore
import java.io.File

/**
 * Loads the host identity once and keeps it. A device that has paired remembers our
 * identifier and public key, so the identity is generated exactly once per install and
 * then read back on every start.
 */
object IdentityStorage {
    private const val FILE_NAME = "host-identity"

    fun loadOrCreate(context: Context, vault: KeystoreVault = KeystoreVault(context)): HostIdentity {
        val stored = try {
            vault.read(FILE_NAME)
        } catch (failure: Exception) {
            // A keystore key can disappear, for example after a restore to new hardware.
            // The old identity is then unreadable and a new one is the only way forward.
            Log.w(LogTag.SERVER, "the stored identity could not be read: ${failure.describe()}")
            null
        }
        if (stored != null) {
            runCatching { HostIdentity.decode(stored) }
                .onSuccess { return it }
                .onFailure { Log.w(LogTag.SERVER, "the stored identity was unusable: ${it.describe()}") }
        }
        val identity = HostIdentity.generate(name = defaultName())
        vault.write(FILE_NAME, identity.encode())
        Log.i(LogTag.SERVER, "generated a new host identity")
        return identity
    }

    private fun defaultName(): String {
        val model = listOf(Build.MANUFACTURER, Build.MODEL)
            .filter { it.isNotBlank() }
            .joinToString(" ")
            .trim()
        return if (model.isEmpty()) "SideJIT Server" else "SideJIT on $model"
    }
}

/** Pairing records, one encrypted file each, under the app private vault. */
class VaultPairingStore(context: Context) : PairingStore {
    private val vault = KeystoreVault(context)
    private val directory = File(context.filesDir, "vault")

    override fun save(record: PairingRecord) {
        vault.write(fileName(record.peer.identifier), record.encode())
        Log.i(LogTag.PAIRING, "stored the pairing for ${record.peer.model}")
    }

    override fun load(identifier: String): PairingRecord? {
        val stored = try {
            vault.read(fileName(identifier))
        } catch (failure: Exception) {
            Log.w(LogTag.PAIRING, "a pairing record could not be read: ${failure.describe()}")
            return null
        } ?: return null
        return runCatching { PairingRecord.decode(stored) }
            .onFailure { Log.w(LogTag.PAIRING, "a pairing record was unusable: ${it.describe()}") }
            .getOrNull()
    }

    override fun all(): List<PairingRecord> {
        val names = directory.list().orEmpty().filter { it.startsWith(PREFIX) && !it.endsWith(".new") }
        return names.mapNotNull { name ->
            val stored = runCatching { vault.read(name) }.getOrNull() ?: return@mapNotNull null
            runCatching { PairingRecord.decode(stored) }.getOrNull()
        }
    }

    override fun delete(identifier: String) {
        vault.delete(fileName(identifier))
    }

    /** The identifier is a UUID from the device; keep only characters safe in a file name. */
    private fun fileName(identifier: String): String =
        PREFIX + identifier.filter { it.isLetterOrDigit() || it == '-' }.take(64)

    companion object {
        private const val PREFIX = "pairing-"
    }
}