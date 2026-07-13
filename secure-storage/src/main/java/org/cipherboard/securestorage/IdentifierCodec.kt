package org.cipherboard.securestorage

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal object IdentifierCodec {
    fun contactKey(contactId: ByteArray): String = digest("contact", contactId)
    fun operationKey(operationId: ByteArray): String = digest("operation", operationId)
    fun displayKey(messageId: ByteArray): String = digest("display", messageId)
    fun replayKey(contactId: ByteArray, messageId: ByteArray): String =
        digest("replay", contactId, messageId)

    private fun digest(domain: String, vararg parts: ByteArray): String {
        parts.forEach { require(it.size in MIN_ID_BYTES..MAX_ID_BYTES) { "Identifier has invalid length" } }
        val messageDigest = MessageDigest.getInstance("SHA-256")
        val domainBytes = "CipherBoard/VaultId/v1/$domain".toByteArray(StandardCharsets.US_ASCII)
        messageDigest.update(intBytes(domainBytes.size))
        messageDigest.update(domainBytes)
        parts.forEach {
            messageDigest.update(intBytes(it.size))
            messageDigest.update(it)
        }
        val digest = messageDigest.digest()
        return try {
            buildString(digest.size * 2) {
                digest.forEach { byte -> append(HEX[(byte.toInt() ushr 4) and 0xf]).append(HEX[byte.toInt() and 0xf]) }
            }
        } finally {
            digest.wipe()
        }
    }

    private fun intBytes(value: Int): ByteArray = ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value).array()

    private const val MIN_ID_BYTES = 8
    private const val MAX_ID_BYTES = 128
    private const val HEX = "0123456789abcdef"
}
