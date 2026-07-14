// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import helium314.keyboard.secure.SecureComposerActivity
import helium314.keyboard.secure.decrypt.DecryptFailureReason
import helium314.keyboard.secure.decrypt.DecryptOperation
import helium314.keyboard.secure.decrypt.DecryptResult
import helium314.keyboard.secure.decrypt.DecryptedContactStatus
import helium314.keyboard.secure.decrypt.DecryptedMessage
import helium314.keyboard.secure.decrypt.LegacyDeviceCredentialHost
import helium314.keyboard.secure.decrypt.ParseFailureReason
import helium314.keyboard.secure.decrypt.ParseResult
import helium314.keyboard.secure.decrypt.ParsedCiphertext
import helium314.keyboard.secure.decrypt.SecureDecryptBackend
import helium314.keyboard.secure.decrypt.SecureDisplayLease
import helium314.keyboard.secure.decrypt.SecureReplyToken
import helium314.keyboard.secure.decrypt.WipeablePlaintext
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.CryptoCoreException
import org.cipherboard.cryptocore.CryptoErrorCode
import org.cipherboard.cryptocore.EnvelopeMetadata
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.VaultLockedException
import java.security.MessageDigest
import java.io.Closeable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean

/** Connects the exported selected-text UI to the crash-safe application runtime. */
class RuntimeSecureDecryptBackend(
    private val runtime: SecureKeyboardRuntime,
    private val context: Context,
    private val crypto: CipherBoardCrypto = CipherBoardCrypto(),
) : SecureDecryptBackend, Closeable {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "cipherboard-decrypt").apply { isDaemon = true }
    }

    override fun parse(parts: List<String>): ParseResult {
        if (parts.isEmpty()) {
            return ParseResult.Failure(ParseFailureReason.INVALID_FORMAT)
        }
        if (parts.size > MAX_PRESENTATION_TOKENS) {
            return ParseResult.Failure(ParseFailureReason.TOO_MANY_PARTS)
        }
        return try {
            val presentationText = joinBoundedPresentation(parts)
                ?: return ParseResult.Failure(ParseFailureReason.TOO_MANY_PARTS)
            val canonicalParts = crypto.decodePresentation(presentationText).parts
            if (canonicalParts.isEmpty() || canonicalParts.size > MAX_PARTS) {
                return ParseResult.Failure(ParseFailureReason.TOO_MANY_PARTS)
            }
            val metadata = ArrayList<EnvelopeMetadata>(canonicalParts.size)
            try {
                canonicalParts.forEach { metadata += crypto.parseEnvelope(it) }
                val first = metadata.first()
                val partNumbers = metadata.map { it.partNumber }.toSet()
                if (first.totalParts != canonicalParts.size ||
                    partNumbers.size != canonicalParts.size ||
                    (1..canonicalParts.size).any { it !in partNumbers } ||
                    metadata.any {
                        it.totalParts != first.totalParts ||
                            !it.messageId.contentEquals(first.messageId) ||
                            !it.routingTag.contentEquals(first.routingTag)
                    }
                ) {
                    ParseResult.Failure(ParseFailureReason.INCONSISTENT_PARTS)
                } else {
                    ParseResult.Success(RuntimeParsedCiphertext(canonicalParts))
                }
            } finally {
                metadata.forEach {
                    it.messageId.fill(0)
                    it.routingTag.fill(0)
                }
            }
        } catch (error: CryptoCoreException) {
            ParseResult.Failure(error.reason.toParseFailure())
        } catch (_: RuntimeException) {
            ParseResult.Failure(ParseFailureReason.INVALID_FORMAT)
        }
    }

    private fun joinBoundedPresentation(tokens: List<String>): String? {
        if (tokens.size == 1) {
            return tokens.single().takeIf { it.length <= MAX_PRESENTATION_CHARS }
        }
        var length = 0
        tokens.forEachIndexed { index, token ->
            length = try {
                val tokenLength = Math.addExact(token.length, if (index == 0) 0 else 1)
                Math.addExact(length, tokenLength)
            } catch (_: ArithmeticException) {
                return null
            }
            if (length > MAX_PRESENTATION_CHARS) return null
        }
        return buildString(length) {
            tokens.forEachIndexed { index, token ->
                if (index > 0) append('\n')
                append(token)
            }
        }
    }

    override fun decrypt(
        host: FragmentActivity,
        parsed: ParsedCiphertext,
        callback: (DecryptResult) -> Unit,
    ): DecryptOperation {
        val request = parsed as? RuntimeParsedCiphertext
            ?: return DecryptOperation { }.also {
                callback(DecryptResult.Failure(DecryptFailureReason.INVALID_CIPHERTEXT))
            }
        val operation = RuntimeDecryptOperation(callback)
        ContextCompat.getMainExecutor(host).execute {
            if (operation.isCancelled) return@execute
            if (runtime.isVaultUnlocked) {
                decryptOnWorker(operation, request.parts())
            } else {
                runCatching { runtime.prepareUnlock() }
                    .onSuccess { unlock -> handleUnlock(host, operation, request, unlock) }
                    .onFailure { operation.fail(DecryptFailureReason.VAULT_LOCKED) }
            }
        }
        return operation
    }

    override fun decryptUnlocked(
        parsed: ParsedCiphertext,
        callback: (DecryptResult) -> Unit,
    ): DecryptOperation {
        val request = parsed as? RuntimeParsedCiphertext
            ?: return DecryptOperation { }.also {
                callback(DecryptResult.Failure(DecryptFailureReason.INVALID_CIPHERTEXT))
            }
        val operation = RuntimeDecryptOperation(callback)
        if (!runtime.isVaultUnlocked) {
            operation.fail(DecryptFailureReason.VAULT_LOCKED)
            return operation
        }
        val parts = try {
            request.parts()
        } catch (_: RuntimeException) {
            operation.fail(DecryptFailureReason.INVALID_CIPHERTEXT)
            return operation
        }
        decryptOnWorker(operation, parts)
        return operation
    }

    override fun canDisplayPlaintext(): Boolean {
        runtime.lockIfExpired()
        return runtime.isVaultUnlocked
    }

    private fun handleUnlock(
        host: FragmentActivity,
        operation: RuntimeDecryptOperation,
        parsed: RuntimeParsedCiphertext,
        action: VaultUnlockAction,
    ) {
        when (action) {
            is VaultUnlockAction.Unlocked -> decryptOnWorker(operation, parsed.parts())
            is VaultUnlockAction.KeyInvalidated -> operation.fail(DecryptFailureReason.SESSION_ERROR)
            is VaultUnlockAction.AuthenticationRequired -> {
                if (action.requiresLegacyConfirmCredential) {
                    val legacyHost = host as? LegacyDeviceCredentialHost
                    val launched = legacyHost?.requestLegacyDeviceCredential { authenticated ->
                        if (operation.isCancelled) return@requestLegacyDeviceCredential
                        if (!authenticated) {
                            operation.fail(DecryptFailureReason.AUTHENTICATION_CANCELLED)
                            return@requestLegacyDeviceCredential
                        }
                        runCatching { runtime.completePromptAuthentication(action) }
                            .onSuccess { completed -> handleCompletedUnlock(operation, parsed, completed) }
                            .onFailure { operation.fail(DecryptFailureReason.VAULT_LOCKED) }
                    } == true
                    if (!launched) operation.fail(DecryptFailureReason.VAULT_LOCKED)
                    return
                }
                val prompt = biometricPrompt(host, operation) { _ ->
                    runCatching { runtime.completePromptAuthentication(action) }
                        .onSuccess { completed -> handleCompletedUnlock(operation, parsed, completed) }
                        .onFailure { operation.fail(DecryptFailureReason.VAULT_LOCKED) }
                }
                operation.attachPrompt(prompt)
                prompt.authenticate(promptInfo(host, action.allowedAuthenticators))
            }
            is VaultUnlockAction.CryptoObjectAuthenticationRequired -> {
                val cryptoObject = action.cryptoObject as? BiometricPrompt.CryptoObject
                if (cryptoObject == null) {
                    operation.fail(DecryptFailureReason.INTERNAL_ERROR)
                    return
                }
                val prompt = biometricPrompt(host, operation) { result ->
                    val authenticatedCryptoObject = result.cryptoObject
                    if (authenticatedCryptoObject == null) {
                        operation.fail(DecryptFailureReason.VAULT_LOCKED)
                        return@biometricPrompt
                    }
                    runCatching {
                        runtime.completeCryptoObjectAuthentication(action, authenticatedCryptoObject)
                    }
                        .onSuccess { completed -> handleCompletedUnlock(operation, parsed, completed) }
                        .onFailure { operation.fail(DecryptFailureReason.VAULT_LOCKED) }
                }
                operation.attachPrompt(prompt)
                prompt.authenticate(promptInfo(host, action.allowedAuthenticators), cryptoObject)
            }
        }
    }

    private fun handleCompletedUnlock(
        operation: RuntimeDecryptOperation,
        parsed: RuntimeParsedCiphertext,
        action: VaultUnlockAction,
    ) {
        if (action is VaultUnlockAction.Unlocked) {
            decryptOnWorker(operation, parsed.parts())
        } else {
            operation.fail(DecryptFailureReason.VAULT_LOCKED)
        }
    }

    private fun biometricPrompt(
        host: FragmentActivity,
        operation: RuntimeDecryptOperation,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    ) = BiometricPrompt(
        host,
        ContextCompat.getMainExecutor(host),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (!operation.isCancelled) onSuccess(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                operation.fail(DecryptFailureReason.AUTHENTICATION_CANCELLED)
            }

            override fun onAuthenticationFailed() = Unit
        },
    )

    private fun promptInfo(host: Activity, allowed: Int): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(host.getString(R.string.secure_unlock_vault))
            .setSubtitle(host.getString(R.string.secure_unlock_vault_description))
            .setAllowedAuthenticators(allowed)
        if (allowed and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
            builder.setNegativeButtonText(host.getString(android.R.string.cancel))
        }
        return builder.build()
    }

    private fun decryptOnWorker(operation: RuntimeDecryptOperation, parts: List<String>) {
        operation.attachFuture(worker.submit {
            if (operation.isCancelled) return@submit
            try {
                val runtimeMessage = runtime.decrypt(parts)
                try {
                    val contactId = runtimeMessage.contactId()
                    val messageId = runtimeMessage.messageId()
                    try {
                        val contact = findContact(contactId)
                        var plaintextOwner: WipeablePlaintext? = WipeablePlaintext.takeOwnership(
                            runtimeMessage.consumePlaintext(ByteArray::copyOf),
                        )
                        var replyToken: RuntimeReplyToken? = null
                        var displayLease: RuntimeDisplayLease? = null
                        var message: DecryptedMessage? = null
                        try {
                            replyToken = RuntimeReplyToken(contactId)
                            displayLease = RuntimeDisplayLease(runtime, messageId)
                            message = DecryptedMessage(
                                plaintext = checkNotNull(plaintextOwner),
                                localContactLabel = contact?.localName.orEmpty(),
                                contactStatus = if (
                                    contact?.verificationStatus == ContactVerificationStatus.VERIFIED
                                ) {
                                    DecryptedContactStatus.VERIFIED
                                } else {
                                    DecryptedContactStatus.UNVERIFIED
                                },
                                replyToken = replyToken,
                                displayLease = displayLease,
                            )
                            plaintextOwner = null
                            replyToken = null
                            displayLease = null
                            val delivered = message
                            message = null
                            operation.succeed(delivered)
                        } finally {
                            message?.close()
                            plaintextOwner?.close()
                            replyToken?.close()
                            displayLease?.close()
                        }
                    } finally {
                        messageId.fill(0)
                        contactId.fill(0)
                    }
                } finally {
                    runtimeMessage.close()
                }
            } catch (error: Throwable) {
                // The ratchet may already have advanced and committed an encrypted pending-display
                // record. Preserve it until a viewer actually renders the plaintext so a viewer
                // interruption cannot make the message unrecoverable.
                operation.fail(error.toDecryptFailure())
            }
        })
    }

    private fun findContact(contactId: ByteArray): SecureContactSummary? =
        runtime.listContacts().firstOrNull { contact ->
            val candidate = contact.internalId()
            try {
                candidate.contentEquals(contactId)
            } finally {
                candidate.fill(0)
            }
        }

    override fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean {
        val reply = token as? RuntimeReplyToken ?: return false
        val contactId = reply.contactId()
        return try {
            host.startActivity(Intent(host, SecureComposerActivity::class.java).apply {
                putExtra(SecureComposerActivity.EXTRA_REPLY_CONTACT_ID, contactId)
            })
            true
        } finally {
            contactId.fill(0)
        }
    }

    override val viewerTimeoutMillis: Long
        get() = ViewerTimeoutPreferences.read(context).millis

    override fun close() {
        worker.shutdownNow()
    }

    private fun CryptoErrorCode.toParseFailure(): ParseFailureReason = when (this) {
        CryptoErrorCode.UNSUPPORTED_VERSION -> ParseFailureReason.UNSUPPORTED_VERSION
        CryptoErrorCode.MISSING_PART -> ParseFailureReason.MISSING_PART
        CryptoErrorCode.INCONSISTENT_PARTS -> ParseFailureReason.INCONSISTENT_PARTS
        CryptoErrorCode.TOO_MANY_PARTS, CryptoErrorCode.SIZE_LIMIT -> ParseFailureReason.TOO_MANY_PARTS
        CryptoErrorCode.WRONG_CONTACT -> ParseFailureReason.WRONG_CONTACT
        else -> ParseFailureReason.INVALID_FORMAT
    }

    private fun Throwable.toDecryptFailure(): DecryptFailureReason = decryptFailureFor(this)

    private companion object {
        const val MAX_PARTS = 128
        const val MAX_PRESENTATION_TOKENS = 32 * 1024
        const val MAX_PRESENTATION_CHARS = 384 * 1024
    }
}

internal fun decryptFailureFor(error: Throwable): DecryptFailureReason = when (error) {
    is VaultLockedException -> DecryptFailureReason.VAULT_LOCKED
    is SecureRuntimeException -> when (error.reason) {
            SecureRuntimeError.WRONG_CONTACT, SecureRuntimeError.CONTACT_NOT_FOUND ->
                DecryptFailureReason.WRONG_CONTACT
            SecureRuntimeError.REPLAY -> DecryptFailureReason.REPLAY
            SecureRuntimeError.INVALID_PARTS -> DecryptFailureReason.INVALID_CIPHERTEXT
            SecureRuntimeError.CONTACT_NOT_READY -> DecryptFailureReason.KEY_CHANGED
            SecureRuntimeError.RATCHET_NOT_FOUND,
            SecureRuntimeError.RATCHET_REVISION_CONFLICT,
            SecureRuntimeError.CORRUPT_STATE,
            -> DecryptFailureReason.SESSION_ERROR
            else -> DecryptFailureReason.INTERNAL_ERROR
        }
    is CryptoCoreException -> when (error.reason) {
        CryptoErrorCode.REPLAY -> DecryptFailureReason.REPLAY
        CryptoErrorCode.WRONG_CONTACT -> DecryptFailureReason.WRONG_CONTACT
        CryptoErrorCode.MISSING_PART -> DecryptFailureReason.MISSING_PART
        CryptoErrorCode.INVALID_STATE -> DecryptFailureReason.SESSION_ERROR
        CryptoErrorCode.INVALID_INPUT,
        CryptoErrorCode.SIZE_LIMIT,
        CryptoErrorCode.UNSUPPORTED_VERSION,
        CryptoErrorCode.INVALID_ENCODING,
        CryptoErrorCode.MISSING_FIELD,
        CryptoErrorCode.DUPLICATE_FIELD,
        CryptoErrorCode.UNKNOWN_MANDATORY_FIELD,
        CryptoErrorCode.INVALID_SIGNATURE,
        CryptoErrorCode.INVALID_TRANSCRIPT,
        CryptoErrorCode.CRYPTO_FAILURE,
        CryptoErrorCode.INCONSISTENT_PARTS,
        CryptoErrorCode.TOO_MANY_PARTS,
        CryptoErrorCode.INVALID_UTF8,
        -> DecryptFailureReason.INVALID_CIPHERTEXT
        CryptoErrorCode.EXPIRED_OFFER,
        CryptoErrorCode.PAIRING_ALREADY_USED,
        CryptoErrorCode.RANDOM_FAILURE,
        CryptoErrorCode.UNKNOWN,
        -> DecryptFailureReason.INTERNAL_ERROR
    }
    else -> DecryptFailureReason.INTERNAL_ERROR
}

private class RuntimeParsedCiphertext(source: List<String>) : ParsedCiphertext {
    private var value: List<String>? = source.toList()

    @Synchronized
    fun parts(): List<String> = value ?: throw IllegalStateException("Parsed ciphertext is closed")

    @Synchronized
    override fun close() {
        value = null
    }

    override fun toString(): String = "RuntimeParsedCiphertext(redacted)"
}

private class RuntimeReplyToken(contactId: ByteArray) : SecureReplyToken {
    private var value: ByteArray? = contactId.copyOf()

    @Synchronized
    fun contactId(): ByteArray = value?.copyOf() ?: throw IllegalStateException("Reply token is closed")

    @Synchronized
    override fun matchesContact(candidateId: ByteArray): Boolean =
        value?.let { MessageDigest.isEqual(it, candidateId) } == true

    @Synchronized
    override fun close() {
        value?.fill(0)
        value = null
    }
}

private class RuntimeDisplayLease(
    private val runtime: SecureKeyboardRuntime,
    messageId: ByteArray,
) : SecureDisplayLease {
    private var value: ByteArray? = messageId.copyOf()
    private var displayed = false

    @Synchronized
    override fun markDisplayed() {
        check(value != null) { "Display lease is closed" }
        displayed = true
    }

    @Synchronized
    override fun close() {
        val id = value ?: return
        value = null
        try {
            if (displayed) runtime.discardPendingDisplay(id)
        } finally {
            id.fill(0)
        }
    }
}

internal class RuntimeDecryptOperation(
    private val callback: (DecryptResult) -> Unit,
) : DecryptOperation {
    private val completed = AtomicBoolean(false)
    @Volatile private var prompt: BiometricPrompt? = null
    @Volatile private var future: Future<*>? = null

    val isCancelled: Boolean
        get() = completed.get()

    fun attachPrompt(value: BiometricPrompt) {
        if (completed.get()) value.cancelAuthentication() else prompt = value
    }

    fun attachFuture(value: Future<*>) {
        if (completed.get()) value.cancel(true) else future = value
    }

    fun succeed(message: DecryptedMessage) {
        if (completed.compareAndSet(false, true)) {
            try {
                callback(DecryptResult.Success(message))
            } catch (error: Throwable) {
                message.close()
                throw error
            }
        } else {
            message.close()
        }
    }

    fun fail(reason: DecryptFailureReason) {
        if (completed.compareAndSet(false, true)) callback(DecryptResult.Failure(reason))
    }

    override fun cancel() {
        if (!completed.compareAndSet(false, true)) return
        prompt?.cancelAuthentication()
        future?.cancel(true)
    }
}
