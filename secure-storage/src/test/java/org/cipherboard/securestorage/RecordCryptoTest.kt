package org.cipherboard.securestorage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.SecureRandom

class RecordCryptoTest {
    private val random = SecureRandom()
    private val crypto = RecordCrypto(random)

    @Test
    fun roundTripUsesFreshNonceAndAuthenticatesMetadata() {
        val dek = ByteArray(32).also(random::nextBytes)
        val plaintext = "ratchet-state".encodeToByteArray()
        try {
            val first = crypto.encrypt(dek, 1, "record", 1, 7, plaintext)
            val second = crypto.encrypt(dek, 1, "record", 1, 7, plaintext)

            assertFalse(first.nonce.contentEquals(second.nonce))
            assertArrayEquals(plaintext, crypto.decrypt(dek, 1, "record", first))
            assertThrows(VaultCorruptException::class.java) {
                crypto.decrypt(dek, 1, "other-record", first)
            }
            assertThrows(VaultCorruptException::class.java) {
                crypto.decrypt(dek, 1, "record", first.copy(revision = 8))
            }
        } finally {
            dek.wipe()
            plaintext.wipe()
        }
    }

    @Test
    fun tamperingIsRejected() {
        val dek = ByteArray(32).also(random::nextBytes)
        val plaintext = ByteArray(128).also(random::nextBytes)
        try {
            val encrypted = crypto.encrypt(dek, 2, "pending", 1, 1, plaintext)
            encrypted.ciphertext[encrypted.ciphertext.lastIndex] =
                (encrypted.ciphertext.last().toInt() xor 1).toByte()
            assertThrows(VaultCorruptException::class.java) {
                crypto.decrypt(dek, 2, "pending", encrypted)
            }
        } finally {
            dek.wipe()
            plaintext.wipe()
        }
    }
}
