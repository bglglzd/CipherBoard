package org.cipherboard.securestorage

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.UserManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import java.security.SecureRandom
import java.nio.charset.StandardCharsets
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Generates a non-exportable Android Keystore key and uses it only to wrap a random 256-bit DEK.
 * The raw DEK is returned as an owned, wipeable buffer only after successful authentication.
 */
class AndroidVaultKeyManager(
    context: Context,
    private val random: SecureRandom = SecureRandom(),
) {
    private val appContext = context.applicationContext
    private val envelopeStore = WrappedDekFileStore(appContext)
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    @Synchronized
    @Throws(VaultStorageException::class, VaultCorruptException::class)
    fun prepareUnlock(
        requestedMode: VaultAuthenticationMode = VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
        forceFreshAuthentication: Boolean = false,
    ): VaultUnlockRequest {
        ensureCredentialStorageAvailable()
        val envelope = envelopeStore.read()
        val operation = if (envelope == null) VaultOperation.CREATE else VaultOperation.OPEN
        return try {
            val mode = envelope?.authenticationMode ?: requestedMode
            val alias = envelope?.alias ?: aliasFor(mode)
            val generatedInfo = if (envelope == null) ensureKey(alias, mode) else null
            val protectionInfo = generatedInfo ?: keyProtectionInfo(
                alias,
                mode,
                checkNotNull(envelope).protectionInfo,
            )
            when (mode) {
                VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT -> {
                    val cipher = initCipher(alias, mode, operation, envelope, protectionInfo)
                    VaultUnlockRequest.CryptoObjectAuthentication(
                        operation = operation,
                        cryptoObject = BiometricPrompt.CryptoObject(cipher),
                        envelope = envelope,
                        protectionInfo = protectionInfo,
                    )
                }
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL -> {
                    if (forceFreshAuthentication) {
                        promptRequest(operation, mode)
                    } else {
                        completeTimeBoundOperation(alias, operation, envelope, protectionInfo)
                    }
                }
            }
        } catch (_: UserNotAuthenticatedException) {
            promptRequest(operation, envelope?.authenticationMode ?: requestedMode)
        } catch (_: KeyPermanentlyInvalidatedException) {
            VaultUnlockRequest.KeyInvalidated(operation)
        } catch (e: GeneralSecurityException) {
            throw VaultStorageException("Cannot prepare Vault key operation", e)
        }
    }

    @Synchronized
    @Throws(VaultStorageException::class, VaultCorruptException::class)
    fun completeCryptoObjectAuthentication(
        request: VaultUnlockRequest.CryptoObjectAuthentication,
        authenticatedCryptoObject: BiometricPrompt.CryptoObject,
    ): VaultUnlockRequest {
        ensureCredentialStorageAvailable()
        if (request.cryptoObject.cipher !== authenticatedCryptoObject.cipher) {
            throw VaultStorageException("Authentication returned an unexpected Cipher")
        }
        val cipher = authenticatedCryptoObject.cipher
            ?: throw VaultStorageException("Authentication result has no Cipher")
        return try {
            completeWithCipher(
                operation = request.operation,
                envelope = request.envelope,
                protectionInfo = request.protectionInfo,
                cipher = cipher,
            )
        } catch (_: KeyPermanentlyInvalidatedException) {
            VaultUnlockRequest.KeyInvalidated(request.operation)
        } catch (e: GeneralSecurityException) {
            throw VaultStorageException("Authenticated Vault operation failed", e)
        }
    }

    /** Call only from a successful BiometricPrompt or legacy confirm-credential callback. */
    @Synchronized
    @Throws(VaultStorageException::class, VaultCorruptException::class)
    fun completePromptAuthentication(
        request: VaultUnlockRequest.PromptAuthentication,
    ): VaultUnlockRequest {
        ensureCredentialStorageAvailable()
        val envelope = envelopeStore.read()
        val operation = if (envelope == null) VaultOperation.CREATE else VaultOperation.OPEN
        if (operation != request.operation) throw VaultStorageException("Vault operation changed during authentication")
        val mode = envelope?.authenticationMode ?: request.mode
        if (mode != VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL) {
            throw VaultStorageException("Prompt-only completion is invalid for this key")
        }
        val alias = envelope?.alias ?: aliasFor(mode)
        val protectionInfo = if (envelope == null) {
            ensureKey(alias, mode)
        } else {
            keyProtectionInfo(alias, mode, envelope.protectionInfo)
        }
        return try {
            completeTimeBoundOperation(alias, operation, envelope, protectionInfo)
        } catch (_: UserNotAuthenticatedException) {
            promptRequest(operation, mode)
        } catch (_: KeyPermanentlyInvalidatedException) {
            VaultUnlockRequest.KeyInvalidated(operation)
        } catch (e: GeneralSecurityException) {
            throw VaultStorageException("Vault key was not authorized", e)
        }
    }

    @Synchronized
    fun currentProtectionInfo(): KeyProtectionInfo? {
        val envelope = envelopeStore.read() ?: return null
        return keyProtectionInfo(envelope.alias, envelope.authenticationMode, envelope.protectionInfo)
    }

    /** Destructive recovery after key invalidation. Ratchet/contact storage must be deleted too. */
    @Synchronized
    fun destroyWrappedKeyMaterial() {
        envelopeStore.delete()
        listOf(
            aliasFor(VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT),
            aliasFor(VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL),
        ).forEach { alias ->
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun completeTimeBoundOperation(
        alias: String,
        operation: VaultOperation,
        envelope: WrappedDekEnvelope?,
        protectionInfo: KeyProtectionInfo,
    ): VaultUnlockRequest = completeWithCipher(
        operation,
        envelope,
        protectionInfo,
        initCipher(alias, protectionInfo.authenticationMode, operation, envelope, protectionInfo),
    )

    private fun completeWithCipher(
        operation: VaultOperation,
        envelope: WrappedDekEnvelope?,
        protectionInfo: KeyProtectionInfo,
        cipher: Cipher,
    ): VaultUnlockRequest {
        return when (operation) {
            VaultOperation.CREATE -> {
                if (envelope != null) throw VaultStorageException("Vault already exists")
                val dek = ByteArray(RecordCrypto.DEK_BYTES).also(random::nextBytes)
                try {
                    val wrapped = cipher.doFinal(dek)
                    val newEnvelope = WrappedDekEnvelope(
                        alias = aliasFor(protectionInfo.authenticationMode),
                        authenticationMode = protectionInfo.authenticationMode,
                        protectionInfo = protectionInfo,
                        nonce = cipher.iv.copyOf(),
                        ciphertext = wrapped,
                    )
                    envelopeStore.write(newEnvelope)
                    VaultUnlockRequest.Unlocked(
                        VaultOperation.CREATE,
                        UnlockedVaultMaterial(protectionInfo, OwnedSecret(dek)),
                    )
                } catch (e: Exception) {
                    dek.wipe()
                    throw e
                }
            }
            VaultOperation.OPEN -> {
                val existing = envelope ?: throw VaultCorruptException("Wrapped DEK is missing")
                val dek = try {
                    cipher.doFinal(existing.ciphertext)
                } catch (e: AEADBadTagException) {
                    throw VaultCorruptException("Wrapped DEK authentication failed", e)
                }
                if (dek.size != RecordCrypto.DEK_BYTES) {
                    dek.wipe()
                    throw VaultCorruptException("Unwrapped DEK has invalid length")
                }
                VaultUnlockRequest.Unlocked(
                    VaultOperation.OPEN,
                    UnlockedVaultMaterial(protectionInfo, OwnedSecret(dek)),
                )
            }
        }
    }

    private fun initCipher(
        alias: String,
        mode: VaultAuthenticationMode,
        operation: VaultOperation,
        envelope: WrappedDekEnvelope?,
        protectionInfo: KeyProtectionInfo,
    ): Cipher {
        val key = keyStore.getKey(alias, null) as? SecretKey
            ?: throw KeyPermanentlyInvalidatedException()
        return Cipher.getInstance(TRANSFORMATION).apply {
            when (operation) {
                VaultOperation.CREATE -> init(Cipher.ENCRYPT_MODE, key, random)
                VaultOperation.OPEN -> {
                    val nonce = envelope?.nonce ?: throw VaultCorruptException("Wrapped DEK nonce is missing")
                    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
                }
            }
            val authenticatedInfo = envelope?.protectionInfo ?: protectionInfo
            val aad = buildWrapAad(alias, mode, authenticatedInfo)
            try {
                updateAAD(aad)
            } finally {
                aad.wipe()
            }
        }
    }

    private fun promptRequest(
        operation: VaultOperation,
        mode: VaultAuthenticationMode,
    ): VaultUnlockRequest.PromptAuthentication {
        val legacy = Build.VERSION.SDK_INT < 30
        val allowed = if (legacy) {
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
        return VaultUnlockRequest.PromptAuthentication(operation, allowed, legacy, mode)
    }

    private fun ensureKey(alias: String, mode: VaultAuthenticationMode): KeyProtectionInfo {
        if (keyStore.containsAlias(alias)) {
            val existing = inspectKey(alias, mode, strongBoxAttempted = false, strongBoxSucceeded = false)
            if (existing.securityLevel == KeystoreSecurityLevel.STRONGBOX ||
                existing.securityLevel == KeystoreSecurityLevel.TRUSTED_ENVIRONMENT
            ) {
                return existing
            }
            keyStore.deleteEntry(alias)
        }
        val strongBoxAttempted = Build.VERSION.SDK_INT >= 28
        if (strongBoxAttempted) {
            try {
                generateKey(alias, mode, strongBox = true)
                val generated = inspectKey(alias, mode, strongBoxAttempted = true, strongBoxSucceeded = true)
                if (generated.securityLevel == KeystoreSecurityLevel.STRONGBOX) return generated
                if (generated.securityLevel == KeystoreSecurityLevel.TRUSTED_ENVIRONMENT) {
                    return generated.copy(strongBoxGenerationSucceeded = false)
                }
                keyStore.deleteEntry(alias)
            } catch (_: StrongBoxUnavailableException) {
                // Expected on devices without StrongBox support for this key configuration.
                runCatching { keyStore.deleteEntry(alias) }
            } catch (e: ProviderException) {
                if (e.cause !is StrongBoxUnavailableException) throw e
                runCatching { keyStore.deleteEntry(alias) }
            }
        }
        generateKey(alias, mode, strongBox = false)
        return requireHardwareBacked(
            alias,
            inspectKey(alias, mode, strongBoxAttempted, strongBoxSucceeded = false),
        )
    }

    private fun generateKey(alias: String, mode: VaultAuthenticationMode, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= 30) {
            val authType = when (mode) {
                VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT ->
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL ->
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            }
            val duration = if (mode == VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT) {
                0
            } else {
                AUTHORIZATION_WINDOW_SECONDS
            }
            builder.setUserAuthenticationParameters(duration, authType)
        } else {
            val duration = if (mode == VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT) {
                -1
            } else {
                AUTHORIZATION_WINDOW_SECONDS
            }
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(duration)
        }
        if (Build.VERSION.SDK_INT >= 24 &&
            mode == VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT
        ) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }
        if (Build.VERSION.SDK_INT >= 28) builder.setIsStrongBoxBacked(strongBox)

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(builder.build())
            generateKey()
        }
    }

    private fun keyProtectionInfo(
        alias: String,
        mode: VaultAuthenticationMode,
        persisted: KeyProtectionInfo?,
    ): KeyProtectionInfo {
        if (!keyStore.containsAlias(alias)) {
            throw KeyPermanentlyInvalidatedException()
        }
        return requireHardwareBacked(
            alias,
            inspectKey(
                alias,
                mode,
                persisted?.strongBoxAttempted ?: false,
                persisted?.strongBoxGenerationSucceeded ?: false,
            ),
        )
    }

    private fun requireHardwareBacked(alias: String, info: KeyProtectionInfo): KeyProtectionInfo {
        if (info.securityLevel == KeystoreSecurityLevel.STRONGBOX ||
            info.securityLevel == KeystoreSecurityLevel.TRUSTED_ENVIRONMENT
        ) {
            return info
        }
        throw VaultStorageException("Vault requires a hardware-backed Android Keystore key for $alias")
    }

    @Suppress("DEPRECATION")
    private fun inspectKey(
        alias: String,
        mode: VaultAuthenticationMode,
        strongBoxAttempted: Boolean,
        strongBoxSucceeded: Boolean,
    ): KeyProtectionInfo {
        val key = keyStore.getKey(alias, null) as SecretKey
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val level = if (Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeystoreSecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeystoreSecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeystoreSecurityLevel.SOFTWARE
                else -> KeystoreSecurityLevel.UNKNOWN
            }
        } else if (strongBoxSucceeded && info.isInsideSecureHardware) {
            KeystoreSecurityLevel.STRONGBOX
        } else if (info.isInsideSecureHardware) {
            KeystoreSecurityLevel.TRUSTED_ENVIRONMENT
        } else {
            KeystoreSecurityLevel.SOFTWARE
        }
        return KeyProtectionInfo(level, strongBoxAttempted, strongBoxSucceeded, mode)
    }

    private fun ensureCredentialStorageAvailable() {
        if (Build.VERSION.SDK_INT < 24) return
        val userManager = appContext.getSystemService(UserManager::class.java)
        if (userManager?.isUserUnlocked != true) {
            throw VaultLockedException()
        }
        val keyguard = appContext.getSystemService(KeyguardManager::class.java)
        if (keyguard?.isDeviceSecure != true) {
            throw VaultStorageException("A secure device credential is required")
        }
    }

    private fun aliasFor(mode: VaultAuthenticationMode): String = when (mode) {
        VaultAuthenticationMode.BIOMETRIC_STRONG_CRYPTO_OBJECT -> "$ALIAS_PREFIX.biometric"
        VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL -> "$ALIAS_PREFIX.credential"
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS_PREFIX = "org.cipherboard.securekeyboard.vault.kek.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val WRAP_AAD_DOMAIN = "CipherBoard/WrappedDek/v2"
        private const val TAG_BITS = 128
        private const val AUTHORIZATION_WINDOW_SECONDS = 15

        internal fun buildWrapAad(
            alias: String,
            mode: VaultAuthenticationMode,
            protectionInfo: KeyProtectionInfo,
        ): ByteArray = (
            "$WRAP_AAD_DOMAIN|$alias|${mode.name}|${protectionInfo.securityLevel.name}|" +
                "${protectionInfo.strongBoxAttempted}|${protectionInfo.strongBoxGenerationSucceeded}"
            ).toByteArray(StandardCharsets.US_ASCII)
    }
}
