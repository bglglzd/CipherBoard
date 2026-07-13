// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.CryptoCoreException
import org.cipherboard.cryptocore.CryptoErrorCode
import org.cipherboard.securestorage.VaultCorruptException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalSessionFailureTest {
    @Test
    fun vaultCorruptionMarksSessionErrorAtMonotonicActivityTime() {
        var markedAt = -1L
        val source = VaultCorruptException("test fixture corruption")

        val mapped = mapLocalSessionFailure(source, 200, 100) {
            markedAt = it
            true
        }

        assertEquals(200, markedAt)
        assertTrue(mapped is SecureRuntimeException)
        assertEquals(SecureRuntimeError.CORRUPT_STATE, (mapped as SecureRuntimeException).reason)
        assertSame(source, mapped.cause)
    }

    @Test
    fun invalidNativeStateMarksSessionErrorButHostileCiphertextDoesNot() {
        var marks = 0
        val invalidState = CryptoCoreException(CryptoErrorCode.INVALID_STATE.wireValue)
        val mapped = mapLocalSessionFailure(invalidState, 100, 300) {
            marks += 1
            true
        }
        assertEquals(1, marks)
        assertEquals(SecureRuntimeError.CORRUPT_STATE, (mapped as SecureRuntimeException).reason)

        val hostileCiphertext = CryptoCoreException(CryptoErrorCode.CRYPTO_FAILURE.wireValue)
        val unchanged = mapLocalSessionFailure(hostileCiphertext, 100, 300) {
            marks += 1
            true
        }
        assertSame(hostileCiphertext, unchanged)
        assertEquals(1, marks)
    }

    @Test
    fun concurrentContactRevisionIsReportedWithoutMaskingCorruption() {
        val mapped = mapLocalSessionFailure(VaultCorruptException("fixture"), 0, 1) { false }
        assertEquals(
            SecureRuntimeError.CONTACT_REVISION_CONFLICT,
            (mapped as SecureRuntimeException).reason,
        )
    }
}
