package org.cipherboard.securestorage

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal data class EncryptedRecord(
    val schemaVersion: Int,
    val revision: Long,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
) {
    fun wipe() {
        nonce.wipe()
        ciphertext.wipe()
    }
}

internal class RecordCrypto(
    private val random: SecureRandom = SecureRandom(),
) {
    fun encrypt(
        dek: ByteArray,
        kind: Int,
        recordKey: String,
        schemaVersion: Int,
        revision: Long,
        plaintext: ByteArray,
    ): EncryptedRecord {
        require(dek.size == DEK_BYTES) { "Vault DEK must be 256 bits" }
        require(schemaVersion > 0) { "Invalid schema version" }
        require(revision > 0) { "Invalid record revision" }
        require(plaintext.size <= MAX_RECORD_BYTES) { "Record is too large" }
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        var additionalData: ByteArray? = null
        var ciphertext: ByteArray? = null
        var succeeded = false
        try {
            additionalData = aad(kind, recordKey, schemaVersion, revision)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(dek, "AES"),
                GCMParameterSpec(TAG_BITS, nonce),
                random,
            )
            cipher.updateAAD(additionalData)
            ciphertext = cipher.doFinal(plaintext)
            val result = EncryptedRecord(schemaVersion, revision, nonce, checkNotNull(ciphertext))
            succeeded = true
            return result
        } finally {
            additionalData?.wipe()
            if (!succeeded) {
                nonce.wipe()
                ciphertext?.wipe()
            }
        }
    }

    @Throws(VaultCorruptException::class)
    fun decrypt(
        dek: ByteArray,
        kind: Int,
        recordKey: String,
        record: EncryptedRecord,
    ): ByteArray {
        require(dek.size == DEK_BYTES) { "Vault DEK must be 256 bits" }
        if (record.nonce.size != NONCE_BYTES || record.ciphertext.size !in TAG_BYTES..MAX_CIPHERTEXT_BYTES) {
            throw VaultCorruptException("Encrypted record has invalid bounds")
        }
        val aad = aad(kind, recordKey, record.schemaVersion, record.revision)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(dek, "AES"),
                GCMParameterSpec(TAG_BITS, record.nonce),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(record.ciphertext)
        } catch (e: AEADBadTagException) {
            throw VaultCorruptException("Encrypted record authentication failed", e)
        } catch (e: GeneralSecurityException) {
            throw VaultCorruptException("Encrypted record cannot be decrypted", e)
        } finally {
            aad.wipe()
        }
    }

    private fun aad(kind: Int, recordKey: String, schemaVersion: Int, revision: Long): ByteArray {
        val domain = AAD_DOMAIN.toByteArray(StandardCharsets.US_ASCII)
        val key = recordKey.toByteArray(StandardCharsets.US_ASCII)
        require(key.size <= MAX_RECORD_KEY_BYTES) { "Record key is too large" }
        return ByteBuffer.allocate(4 + domain.size + 4 + 4 + key.size + 4 + 8)
            .putInt(domain.size)
            .put(domain)
            .putInt(kind)
            .putInt(key.size)
            .put(key)
            .putInt(schemaVersion)
            .putLong(revision)
            .array()
    }

    companion object {
        const val DEK_BYTES = 32
        const val NONCE_BYTES = 12
        const val TAG_BITS = 128
        const val TAG_BYTES = TAG_BITS / 8
        const val MAX_RECORD_BYTES = 4 * 1024 * 1024
        const val MAX_CIPHERTEXT_BYTES = MAX_RECORD_BYTES + TAG_BYTES
        private const val MAX_RECORD_KEY_BYTES = 256
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val AAD_DOMAIN = "CipherBoard/VaultRecord/v1"
    }
}
