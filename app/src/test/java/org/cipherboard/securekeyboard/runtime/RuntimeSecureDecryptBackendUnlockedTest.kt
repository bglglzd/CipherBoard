// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.content.Context
import helium314.keyboard.secure.decrypt.DecryptFailureReason
import helium314.keyboard.secure.decrypt.DecryptResult
import helium314.keyboard.secure.decrypt.ParseResult
import helium314.keyboard.secure.decrypt.SecureDecryptRuntime
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.EnvelopeMetadata
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.inOrder
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyNoMoreInteractions
import org.mockito.Mockito.`when`

class RuntimeSecureDecryptBackendUnlockedTest {
    @Test
    fun unlockedBridgeFailsClosedWithoutStartingAuthenticationWhenVaultIsLocked() {
        val runtime = mock(SecureKeyboardRuntime::class.java)
        val crypto = mock(CipherBoardCrypto::class.java)
        `when`(runtime.isVaultUnlocked).thenReturn(false)
        `when`(crypto.parseEnvelope(CIPHERTEXT)).thenReturn(
            EnvelopeMetadata(
                routingTag = ByteArray(16) { 1 },
                messageId = ByteArray(16) { 2 },
                partNumber = 1,
                totalParts = 1,
                capabilities = 0,
                olmType = 0,
                payloadBytes = 1,
            ),
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
    }
}
