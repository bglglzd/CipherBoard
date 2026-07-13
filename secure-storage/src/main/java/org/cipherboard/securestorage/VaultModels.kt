package org.cipherboard.securestorage

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import java.io.Closeable

enum class VaultAuthenticationMode {
    /** CryptoObject-bound, authentication-per-use key. Device credential fallback is unavailable. */
    BIOMETRIC_STRONG_CRYPTO_OBJECT,

    /** Strong biometric or device credential, using a short Keystore authorization window. */
    BIOMETRIC_OR_DEVICE_CREDENTIAL,
}

enum class KeystoreSecurityLevel {
    STRONGBOX,
    TRUSTED_ENVIRONMENT,
    SOFTWARE,
    UNKNOWN,
}

data class KeyProtectionInfo(
    val securityLevel: KeystoreSecurityLevel,
    val strongBoxAttempted: Boolean,
    val strongBoxGenerationSucceeded: Boolean,
    val authenticationMode: VaultAuthenticationMode,
)

enum class VaultOperation {
    CREATE,
    OPEN,
}

sealed interface VaultUnlockRequest {
    val operation: VaultOperation

    class CryptoObjectAuthentication internal constructor(
        override val operation: VaultOperation,
        val cryptoObject: BiometricPrompt.CryptoObject,
        val allowedAuthenticators: Int = BiometricManager.Authenticators.BIOMETRIC_STRONG,
        internal val envelope: WrappedDekEnvelope?,
        internal val protectionInfo: KeyProtectionInfo,
    ) : VaultUnlockRequest

    class PromptAuthentication internal constructor(
        override val operation: VaultOperation,
        val allowedAuthenticators: Int,
        /** Android 10 and older require a KeyguardManager confirm-credential Activity. */
        val requiresLegacyConfirmCredential: Boolean,
        internal val mode: VaultAuthenticationMode,
    ) : VaultUnlockRequest

    class Unlocked internal constructor(
        override val operation: VaultOperation,
        val material: UnlockedVaultMaterial,
    ) : VaultUnlockRequest

    data class KeyInvalidated(
        override val operation: VaultOperation,
    ) : VaultUnlockRequest
}

class UnlockedVaultMaterial internal constructor(
    val protectionInfo: KeyProtectionInfo,
    private val ownedDek: OwnedSecret,
) : Closeable {
    internal fun transferDek(): ByteArray = ownedDek.take()
    override fun close() = ownedDek.close()
}

class VaultStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)
class VaultCorruptException(message: String, cause: Throwable? = null) : Exception(message, cause)
class VaultLockedException : IllegalStateException("Vault is locked")
class RatchetRevisionConflictException : IllegalStateException("Ratchet state revision changed")
