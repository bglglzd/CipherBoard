// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import helium314.keyboard.secure.decrypt.DecryptFailureReason
import org.cipherboard.cryptocore.CryptoCoreException
import org.cipherboard.cryptocore.CryptoErrorCode
import org.junit.Assert.assertEquals
import org.junit.Test

class RuntimeDecryptFailureMappingTest {
    @Test
    fun tamperedCiphertextErrorsAreReportedAsInvalidCiphertext() {
        listOf(
            CryptoErrorCode.INVALID_INPUT,
            CryptoErrorCode.INVALID_ENCODING,
            CryptoErrorCode.INVALID_SIGNATURE,
            CryptoErrorCode.INVALID_TRANSCRIPT,
            CryptoErrorCode.CRYPTO_FAILURE,
            CryptoErrorCode.INVALID_UTF8,
        ).forEach { code ->
            assertEquals(
                code.name,
                DecryptFailureReason.INVALID_CIPHERTEXT,
                decryptFailureFor(CryptoCoreException(code.wireValue)),
            )
        }
    }

    @Test
    fun replayAndWrongContactKeepSpecificErrors() {
        assertEquals(
            DecryptFailureReason.REPLAY,
            decryptFailureFor(CryptoCoreException(CryptoErrorCode.REPLAY.wireValue)),
        )
        assertEquals(
            DecryptFailureReason.WRONG_CONTACT,
            decryptFailureFor(CryptoCoreException(CryptoErrorCode.WRONG_CONTACT.wireValue)),
        )
    }
}
