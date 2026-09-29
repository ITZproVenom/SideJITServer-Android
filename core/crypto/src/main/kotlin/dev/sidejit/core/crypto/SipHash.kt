package dev.sidejit.core.crypto

import java.util.Base64

/**
 * SipHash-2-4. Apple uses it to derive the `authTag` a paired device looks for in our
 * mDNS advertisement, which is the only reason this is here.
 */
object SipHash {
    fun hash24(key: ByteArray, message: ByteArray): Long {
        require(key.size == 16) { "a SipHash key is 16 bytes" }
        val k0 = readLongLe(key, 0)
        val k1 = readLongLe(key, 8)
        var v0 = 0x736f6d6570736575uL.toLong() xor k0
        var v1 = 0x646f72616e646f6duL.toLong() xor k1
        var v2 = 0x6c7967656e657261uL.toLong() xor k0
        var v3 = 0x7465646279746573uL.toLong() xor k1

        fun round() {
            v0 += v1; v1 = java.lang.Long.rotateLeft(v1, 13); v1 = v1 xor v0
            v0 = java.lang.Long.rotateLeft(v0, 32)
            v2 += v3; v3 = java.lang.Long.rotateLeft(v3, 16); v3 = v3 xor v2
            v0 += v3; v3 = java.lang.Long.rotateLeft(v3, 21); v3 = v3 xor v0
            v2 += v1; v1 = java.lang.Long.rotateLeft(v1, 17); v1 = v1 xor v2
            v2 = java.lang.Long.rotateLeft(v2, 32)
        }

        val fullBlocks = message.size and 7.inv()
        var offset = 0
        while (offset < fullBlocks) {
            val m = readLongLe(message, offset)
            v3 = v3 xor m
            round(); round()
            v0 = v0 xor m
            offset += 8
        }

        var tail = (message.size.toLong() and 0xFF) shl 56
        var shift = 0
        while (offset < message.size) {
            tail = tail or ((message[offset].toLong() and 0xFF) shl shift)
            shift += 8
            offset++
        }
        v3 = v3 xor tail
        round(); round()
        v0 = v0 xor tail

        v2 = v2 xor 0xFF
        round(); round(); round(); round()
        return v0 xor v1 xor v2 xor v3
    }

    /**
     * The six byte tag Apple publishes as the `authTag` TXT entry: SipHash-2-4 of the
     * identifier under the alternate identity resolving key, taken little endian and
     * then reversed, keeping the first six bytes.
     */
    fun authTag(altIrk: ByteArray, serviceIdentifier: String): ByteArray {
        val value = hash24(altIrk, serviceIdentifier.toByteArray(Charsets.UTF_8))
        val little = ByteArray(8) { ((value ushr (8 * it)) and 0xFF).toByte() }
        return ByteArray(6) { little[5 - it] }
    }

    fun authTagBase64(altIrk: ByteArray, serviceIdentifier: String): String =
        Base64.getEncoder().encodeToString(authTag(altIrk, serviceIdentifier))

    private fun readLongLe(source: ByteArray, offset: Int): Long {
        var value = 0L
        for (index in 0 until 8) {
            value = value or ((source[offset + index].toLong() and 0xFF) shl (8 * index))
        }
        return value
    }
}