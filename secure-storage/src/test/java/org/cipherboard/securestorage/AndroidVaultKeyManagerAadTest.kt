// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securestorage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidVaultKeyManagerAadTest {
    @Test
    fun wrappingAadAuthenticatesAliasModeAndProtectionMetadata() {
        val base = KeyProtectionInfo(
            securityLevel = KeystoreSecurityLevel.STRONGBOX,
            strongBoxAttempted = true,
            strongBoxGenerationSucceeded = true,
            authenticationMode = VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
        )
        val expected = AndroidVaultKeyManager.buildWrapAad(
            "cipherboard.alias",
            VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
            base,
        )
        val variants = listOf(
            AndroidVaultKeyManager.buildWrapAad(
                "other.alias",
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                base,
            ),
            AndroidVaultKeyManager.buildWrapAad(
                "cipherboard.alias",
                VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT,
                base,
            ),
            AndroidVaultKeyManager.buildWrapAad(
                "cipherboard.alias",
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                base.copy(securityLevel = KeystoreSecurityLevel.TRUSTED_ENVIRONMENT),
            ),
            AndroidVaultKeyManager.buildWrapAad(
                "cipherboard.alias",
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                base.copy(strongBoxAttempted = false),
            ),
            AndroidVaultKeyManager.buildWrapAad(
                "cipherboard.alias",
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                base.copy(strongBoxGenerationSucceeded = false),
            ),
        )

        try {
            assertTrue(expected.decodeToString().startsWith("CipherBoard/WrappedDek/v2|"))
            variants.forEach { variant -> assertFalse(expected.contentEquals(variant)) }
        } finally {
            expected.wipe()
            variants.forEach(ByteArray::wipe)
        }
    }
}
