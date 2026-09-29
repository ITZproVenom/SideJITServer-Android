package dev.sidejit.core.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** The hash functions the pairing and tunnel layers need. */
enum class Digest(val jcaName: String, val macName: String, val outputBytes: Int) {
    SHA256("SHA-256", "HmacSHA256", 32),
    SHA512("SHA-512", "HmacSHA512", 64);

    fun hash(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(jcaName)
        for (part in parts) md.update(part)
        return md.digest()
    }
}

object Hmac {
    fun compute(digest: Digest, key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance(digest.macName)
        // An all zero key is legal for HMAC but SecretKeySpec refuses an empty one.
        val material = if (key.isEmpty()) ByteArray(1) else key
        mac.init(SecretKeySpec(material, digest.macName))
        return mac.doFinal(message)
    }
}

/** HKDF as specified by RFC 5869. */
object Hkdf {
    fun extract(digest: Digest, salt: ByteArray, inputKeyMaterial: ByteArray): ByteArray =
        Hmac.compute(digest, salt, inputKeyMaterial)

    fun expand(digest: Digest, pseudoRandomKey: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length >= 0) { "length must not be negative" }
        require(length <= 255 * digest.outputBytes) { "length exceeds what HKDF can produce" }
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            val block = Hmac.compute(
                digest,
                pseudoRandomKey,
                previous + info + byteArrayOf(counter.toByte()),
            )
            val take = minOf(block.size, length - written)
            System.arraycopy(block, 0, output, written, take)
            written += take
            previous = block
            counter++
        }
        return output
    }

    fun derive(
        digest: Digest,
        salt: ByteArray,
        inputKeyMaterial: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray = expand(digest, extract(digest, salt, inputKeyMaterial), info, length)
}