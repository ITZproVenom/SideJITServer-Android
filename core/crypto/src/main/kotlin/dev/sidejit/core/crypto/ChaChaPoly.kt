package dev.sidejit.core.crypto

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

/** ChaCha20-Poly1305 as specified by RFC 8439. */
object ChaChaPoly {
    const val KEY_BYTES: Int = 32
    const val NONCE_BYTES: Int = 12
    const val TAG_BYTES: Int = 16

    class AuthenticationFailure(message: String) : Exception(message)

    /**
     * The pairing protocol names its nonces with short labels such as `PS-Msg05`.
     * The label occupies the tail of the nonce and the leading bytes stay zero.
     */
    fun nonce(label: String): ByteArray {
        val bytes = label.toByteArray(Charsets.US_ASCII)
        require(bytes.size <= NONCE_BYTES) { "the nonce label does not fit in twelve bytes" }
        val nonce = ByteArray(NONCE_BYTES)
        System.arraycopy(bytes, 0, nonce, NONCE_BYTES - bytes.size, bytes.size)
        return nonce
    }

    /** The tunnel numbers its nonces; the counter is little endian in the trailing eight bytes. */
    fun nonce(counter: Long): ByteArray {
        val nonce = ByteArray(NONCE_BYTES)
        for (index in 0 until 8) {
            nonce[4 + index] = ((counter ushr (8 * index)) and 0xFF).toByte()
        }
        return nonce
    }

    /** RPPairing control-channel nonce: [u64 sequence number LE][four zero bytes]. */
    fun rppairingNonce(sequenceNumber: Long): ByteArray {
        val nonce = ByteArray(NONCE_BYTES)
        for (index in 0 until 8) {
            nonce[index] = ((sequenceNumber ushr (8 * index)) and 0xFF).toByte()
        }
        return nonce
    }

    fun seal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray = ByteArray(0),
    ): ByteArray = process(true, key, nonce, plaintext, associatedData)

    @Throws(AuthenticationFailure::class)
    fun open(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray = ByteArray(0),
    ): ByteArray {
        if (ciphertext.size < TAG_BYTES) throw AuthenticationFailure("the ciphertext is shorter than its tag")
        return process(false, key, nonce, ciphertext, associatedData)
    }

    private fun process(
        encrypt: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        associatedData: ByteArray,
    ): ByteArray {
        require(key.size == KEY_BYTES) { "a ChaCha20-Poly1305 key is 32 bytes" }
        require(nonce.size == NONCE_BYTES) { "a ChaCha20-Poly1305 nonce is 12 bytes" }
        val cipher = ChaCha20Poly1305()
        cipher.init(encrypt, AEADParameters(KeyParameter(key), TAG_BYTES * 8, nonce, associatedData))
        val output = ByteArray(cipher.getOutputSize(input.size))
        var written = cipher.processBytes(input, 0, input.size, output, 0)
        written += try {
            cipher.doFinal(output, written)
        } catch (failure: Exception) {
            throw AuthenticationFailure("the ciphertext did not authenticate")
        }
        return if (written == output.size) output else output.copyOf(written)
    }
}