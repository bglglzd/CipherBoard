// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.content.Context
import helium314.keyboard.secure.decrypt.DecryptFailureReason
import helium314.keyboard.secure.decrypt.DecryptResult
import helium314.keyboard.secure.decrypt.ParseResult
import helium314.keyboard.secure.decrypt.SecureDecryptRuntime
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.CryptoCoreException
import org.cipherboard.cryptocore.CryptoErrorCode
import org.cipherboard.cryptocore.EnvelopeMetadata
import org.cipherboard.cryptocore.PresentationDecoded
import org.cipherboard.cryptocore.TransportPresentation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.inOrder
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyNoInteractions
import org.mockito.Mockito.verifyNoMoreInteractions
import org.mockito.Mockito.`when`

class RuntimeSecureDecryptBackendUnlockedTest {
    @Test
    fun unlockedBridgeFailsClosedWithoutStartingAuthenticationWhenVaultIsLocked() {
        val runtime = mock(SecureKeyboardRuntime::class.java)
        val crypto = mock(CipherBoardCrypto::class.java)
        `when`(runtime.isVaultUnlocked).thenReturn(false)
        `when`(crypto.decodePresentation(CIPHERTEXT)).thenReturn(
            PresentationDecoded(TransportPresentation.COMPACT, listOf(CIPHERTEXT)),
        )
        `when`(crypto.parseEnvelope(CIPHERTEXT)).thenReturn(
            metadata(),
        )
        val backend = RuntimeSecureDecryptBackend(runtime, mock(Context::class.java), crypto)
        val backendField = SecureDecryptRuntime::class.java.getDeclaredField("backend").apply {
            isAccessible = true
        }
        val originalBackend = backendField.get(null)

        try {
            backendField.set(null, backend)
            val parsed = backend.parse(listOf(CIPHERTEXT)) as ParseResult.Success
            parsed.parsed.use { handle ->
                var result: DecryptResult? = null
                SecureDecryptRuntime.decryptUnlocked(handle) { result = it }

                assertTrue(result is DecryptResult.Failure)
                assertEquals(
                    DecryptFailureReason.VAULT_LOCKED,
                    (result as DecryptResult.Failure).reason,
                )
                verify(runtime).isVaultUnlocked
                verifyNoMoreInteractions(runtime)
            }
        } finally {
            backendField.set(null, originalBackend)
            backend.close()
        }
    }

    @Test
    fun wordPresentationIsDecodedBeforeMetadataValidationWithoutDecrypting() {
        val runtime = mock(SecureKeyboardRuntime::class.java)
        val crypto = mock(CipherBoardCrypto::class.java)
        val wordText = "that\nwhat\tthis"
        `when`(crypto.decodePresentation(wordText)).thenReturn(
            PresentationDecoded(TransportPresentation.ENGLISH_WORDS, listOf(CIPHERTEXT)),
        )
        `when`(crypto.parseEnvelope(CIPHERTEXT)).thenReturn(metadata())
        val backend = RuntimeSecureDecryptBackend(runtime, mock(Context::class.java), crypto)

        try {
            val result = backend.parse(listOf(wordText))
            assertTrue(result is ParseResult.Success)
            assertFalse(result.toString().contains(wordText))
            assertFalse(result.toString().contains(CIPHERTEXT))
            (result as ParseResult.Success).parsed.close()
            verify(crypto).decodePresentation(wordText)
            verify(crypto).parseEnvelope(CIPHERTEXT)
            verifyNoMoreInteractions(crypto)
            verifyNoInteractions(runtime)
        } finally {
            backend.close()
        }
    }

    @Test
    fun wordDecodeFailuresMapWithoutCallingEnvelopeParserOrRuntime() {
        val cases = listOf(
            CryptoErrorCode.INVALID_ENCODING to helium314.keyboard.secure.decrypt.ParseFailureReason.INVALID_FORMAT,
            CryptoErrorCode.UNSUPPORTED_VERSION to
                helium314.keyboard.secure.decrypt.ParseFailureReason.UNSUPPORTED_VERSION,
            CryptoErrorCode.SIZE_LIMIT to helium314.keyboard.secure.decrypt.ParseFailureReason.TOO_MANY_PARTS,
        )

        cases.forEach { (code, expected) ->
            val runtime = mock(SecureKeyboardRuntime::class.java)
            val crypto = mock(CipherBoardCrypto::class.java)
            `when`(crypto.decodePresentation(WORD_TEXT)).thenThrow(CryptoCoreException(code.wireValue))
            val backend = RuntimeSecureDecryptBackend(runtime, mock(Context::class.java), crypto)
            try {
                val failure = backend.parse(listOf(WORD_TEXT)) as ParseResult.Failure
                assertEquals(expected, failure.reason)
                verify(crypto).decodePresentation(WORD_TEXT)
                verifyNoMoreInteractions(crypto)
                verifyNoInteractions(runtime)
            } finally {
                backend.close()
            }
        }
    }

    @Test
    fun partialMetadataIsWipedWhenLaterCanonicalPartFails() {
        val runtime = mock(SecureKeyboardRuntime::class.java)
        val crypto = mock(CipherBoardCrypto::class.java)
        val parts = listOf("CB1:first", "CB1:second")
        val routingTag = ByteArray(16) { 0x31 }
        val messageId = ByteArray(16) { 0x32 }
        `when`(crypto.decodePresentation(parts.joinToString("\n"))).thenReturn(
            PresentationDecoded(TransportPresentation.COMPACT, parts),
        )
        `when`(crypto.parseEnvelope(parts.first())).thenReturn(
            EnvelopeMetadata(
                routingTag = routingTag,
                messageId = messageId,
                partNumber = 1,
                totalParts = 2,
                capabilities = 0,
                olmType = 0,
                payloadBytes = 1,
            ),
        )
        `when`(crypto.parseEnvelope(parts.last())).thenThrow(
            CryptoCoreException(CryptoErrorCode.INVALID_ENCODING.wireValue),
        )
        val backend = RuntimeSecureDecryptBackend(runtime, mock(Context::class.java), crypto)

        try {
            val failure = backend.parse(parts) as ParseResult.Failure
            assertEquals(
                helium314.keyboard.secure.decrypt.ParseFailureReason.INVALID_FORMAT,
                failure.reason,
            )
            assertTrue(routingTag.all { it == 0.toByte() })
            assertTrue(messageId.all { it == 0.toByte() })
            verifyNoInteractions(runtime)
        } finally {
            backend.close()
        }
    }

    @Test
    fun displayGateAppliesExpiredLockPolicyBeforeReadingVaultState() {
        val runtime = mock(SecureKeyboardRuntime::class.java)
        `when`(runtime.lockIfExpired()).thenReturn(true)
        `when`(runtime.isVaultUnlocked).thenReturn(false)
        val backend = RuntimeSecureDecryptBackend(
            runtime,
            mock(Context::class.java),
            mock(CipherBoardCrypto::class.java),
        )

        try {
            assertEquals(false, backend.canDisplayPlaintext())
            inOrder(runtime).apply {
                verify(runtime).lockIfExpired()
                verify(runtime).isVaultUnlocked
            }
            verifyNoMoreInteractions(runtime)
        } finally {
            backend.close()
        }
    }

    private companion object {
        const val CIPHERTEXT = "CB1:test"
        const val WORD_TEXT = "that what this"

        fun metadata() = EnvelopeMetadata(
            routingTag = ByteArray(16) { 1 },
            messageId = ByteArray(16) { 2 },
            partNumber = 1,
            totalParts = 1,
            capabilities = 0,
            olmType = 0,
            payloadBytes = 1,
        )
    }
}
