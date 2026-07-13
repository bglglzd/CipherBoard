// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securestorage

import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidVaultKeyManagerAuthenticationPolicyTest {
    @Test
    fun legacyAndroidUsesAuthenticationPerUseBiometricForNewVault() {
        for (sdkInt in 23..29) {
            assertEquals(
                VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT,
                AndroidVaultKeyManager.authenticationModeForNewVault(
                    VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                    sdkInt,
                ),
            )
        }
    }

    @Test
    fun android11AndNewerPreservesCredentialFallbackForNewVault() {
        for (sdkInt in listOf(30, 35, 36)) {
            assertEquals(
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                AndroidVaultKeyManager.authenticationModeForNewVault(
                    VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                    sdkInt,
                ),
            )
        }
    }

    @Test
    fun biometricOnlyRequestIsPreservedOnEverySupportedApi() {
        for (sdkInt in listOf(23, 29, 30, 36)) {
            assertEquals(
                VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT,
                AndroidVaultKeyManager.authenticationModeForNewVault(
                    VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT,
                    sdkInt,
                ),
            )
        }
    }
}
