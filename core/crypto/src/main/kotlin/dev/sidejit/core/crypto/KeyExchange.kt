package dev.sidejit.core.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

private val random = SecureRandom()

/** X25519 Diffie-Hellman, RFC 7748. */
object X25519 {
    const val KEY_BYTES: Int = 32

    class KeyPair internal constructor(
        private val privateKey: X25519PrivateKeyParameters,
    ) {
        val publicKey: ByteArray get() = privateKey.generatePublicKey().encoded

        fun agree(peerPublicKey: ByteArray): ByteArray {
            require(peerPublicKey.size == KEY_BYTES) { "an X25519 public key is 32 bytes" }
            val agreement = X25519Agreement()
            agreement.init(privateKey)
            val shared = ByteArray(agreement.agreementSize)
            agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), shared, 0)
            check(!shared.all { it == 0.toByte() }) { "the peer public key produced an all zero secret" }
            return shared
        }
    }

    fun generate(): KeyPair = KeyPair(X25519PrivateKeyParameters(random))

    fun fromPrivateKey(privateKey: ByteArray): KeyPair {
        require(privateKey.size == KEY_BYTES) { "an X25519 private key is 32 bytes" }
        return KeyPair(X25519PrivateKeyParameters(privateKey, 0))
    }
}

/** Ed25519 signatures, RFC 8032. */
object Ed25519 {
    const val SEED_BYTES: Int = 32
    const val PUBLIC_KEY_BYTES: Int = 32
    const val SIGNATURE_BYTES: Int = 64

    class KeyPair internal constructor(private val privateKey: Ed25519PrivateKeyParameters) {
        val seed: ByteArray get() = privateKey.encoded
        val publicKey: ByteArray get() = privateKey.generatePublicKey().encoded

        fun sign(message: ByteArray): ByteArray {
            val signer = Ed25519Signer()
            signer.init(true, privateKey)
            signer.update(message, 0, message.size)
            return signer.generateSignature()
        }
    }

    fun generate(): KeyPair = KeyPair(Ed25519PrivateKeyParameters(random))

    fun fromSeed(seed: ByteArray): KeyPair {
        require(seed.size == SEED_BYTES) { "an Ed25519 seed is 32 bytes" }
        return KeyPair(Ed25519PrivateKeyParameters(seed, 0))
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != PUBLIC_KEY_BYTES) return false
        if (signature.size != SIGNATURE_BYTES) return false
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }
}