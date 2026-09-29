package dev.sidejit.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small secrets kept in app private storage, encrypted with a key that lives in the
 * Android keystore and never leaves it. Losing the keystore key, for example when the
 * user clears the app data or the device is wiped, makes the stored blob unreadable,
 * which is the intended behaviour: the pairing has to be redone rather than silently
 * restored somewhere else.
 */
class KeystoreVault(context: Context, private val alias: String = DEFAULT_ALIAS) {
    private val directory = File(context.filesDir, "vault").apply { mkdirs() }

    fun read(name: String): ByteArray? {
        val file = File(directory, name)
        if (!file.exists()) return null
        val stored = file.readBytes()
        if (stored.size <= IV_BYTES) return null
        val iv = stored.copyOfRange(0, IV_BYTES)
        val ciphertext = stored.copyOfRange(IV_BYTES, stored.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    fun write(name: String, value: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ciphertext = cipher.doFinal(value)
        val temporary = File(directory, "$name.new")
        temporary.writeBytes(cipher.iv + ciphertext)
        if (!temporary.renameTo(File(directory, name))) {
            temporary.delete()
            throw IllegalStateException("could not replace the stored value for $name")
        }
    }

    fun delete(name: String) {
        File(directory, name).delete()
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (store.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // The server has to work while the screen is off and nobody is present,
                // so the key cannot require user authentication.
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    companion object {
        const val DEFAULT_ALIAS: String = "sidejit-vault"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
    }
}