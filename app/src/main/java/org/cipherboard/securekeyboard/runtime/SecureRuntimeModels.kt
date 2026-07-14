// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.TransportPresentation
import org.cipherboard.securestorage.CommittedOutboundReceipt
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.KeyProtectionInfo
import org.cipherboard.securestorage.PendingDisplay
import org.cipherboard.securestorage.PendingOutbound
import org.cipherboard.securestorage.PendingOutboundState
import org.cipherboard.securestorage.VaultOperation
import org.cipherboard.securestorage.VaultUnlockRequest
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

class OwnerIdentitySummary internal constructor(
    val localOwnerName: String,
    identityFingerprint: ByteArray,
    val protocolVersion: Int,
    val createdAtEpochMillis: Long,
) {
    private val fingerprint = identityFingerprint.copyOf()

    fun identityFingerprint(): ByteArray = fingerprint.copyOf()

    override fun toString(): String = "OwnerIdentitySummary(protocolVersion=$protocolVersion)"
}

class SecureContactSummary internal constructor(
    internalId: ByteArray,
    val localName: String,
    identityFingerprint: ByteArray,
    routingTag: ByteArray,
    val verificationStatus: ContactVerificationStatus,
    val pairedAtEpochMillis: Long,
    val lastActiveAtEpochMillis: Long,
    val protocolVersion: Int,
    val safetyNumber: String,
    val safetyCode: String,
    val requiresRepairing: Boolean,
    val sessionError: Boolean,
    val keyChanged: Boolean,
) {
    private val id = internalId.copyOf()
    private val fingerprint = identityFingerprint.copyOf()
    private val tag = routingTag.copyOf()

    fun internalId(): ByteArray = id.copyOf()
    fun identityFingerprint(): ByteArray = fingerprint.copyOf()
    fun routingTag(): ByteArray = tag.copyOf()

    override fun toString(): String =
        "SecureContactSummary(status=$verificationStatus,protocolVersion=$protocolVersion)"
}

internal class ValidatedOutboundDelivery private constructor(
    val text: String,
    val presentation: TransportPresentation,
    parts: List<String>,
) {
    val parts: List<String> = parts.toList()

    companion object {
        fun encode(
            crypto: CipherBoardCrypto,
            parts: List<String>,
            presentation: TransportPresentation,
        ): ValidatedOutboundDelivery {
            val text = crypto.encodePresentation(parts, presentation)
            require(text.length in 1..PreparedOutbound.MAX_DELIVERY_TEXT_CHARS)
            val decoded = crypto.decodePresentation(text)
            check(decoded.presentation == presentation && decoded.parts == parts) {
                "Crypto presentation round-trip mismatch"
            }
            return ValidatedOutboundDelivery(text, presentation, parts)
        }
    }
}

class PreparedOutbound private constructor(
    contactId: ByteArray,
    operationId: ByteArray,
    delivery: ValidatedOutboundDelivery,
    val deliveryState: PendingOutboundState = PendingOutboundState.READY,
    private val markCommitUncertain: ((ByteArray) -> Boolean)? = null,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val boundaryClaimed = AtomicBoolean(false)
    private val contact = contactId.copyOf()
    private val id = operationId.copyOf()
    private var ciphertextParts = delivery.parts
    private var exactDeliveryText = delivery.text

    val presentation: TransportPresentation = delivery.presentation

    val parts: List<String>
        get() = ciphertextParts
    val deliveryText: String
        get() = exactDeliveryText

    fun contactId(): ByteArray = contact.copyOf()
    fun operationId(): ByteArray = id.copyOf()
    val canAutomaticallyRetry: Boolean
        get() = deliveryState == PendingOutboundState.READY && markCommitUncertain != null && !closed.get()

    internal fun claimCommitBoundary(): OutboundCommitBoundary? {
        if (!canAutomaticallyRetry || markCommitUncertain == null) return null
        if (!boundaryClaimed.compareAndSet(false, true)) return null
        return OutboundCommitBoundary(id, markCommitUncertain)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        contact.fill(0)
        id.fill(0)
        ciphertextParts = emptyList()
        exactDeliveryText = ""
    }

    override fun toString(): String =
        "PreparedOutbound(presentation=$presentation,parts=${ciphertextParts.size})"

    internal companion object {
        const val MAX_DELIVERY_TEXT_CHARS = 384 * 1024

        fun fromCommitted(
            receipt: CommittedOutboundReceipt,
            delivery: ValidatedOutboundDelivery,
            markCommitUncertain: (ByteArray) -> Boolean,
        ): PreparedOutbound {
            verifyStoredCiphertext(receipt.pendingCiphertext(), delivery)
            val contactId = receipt.contactId()
            val operationId = receipt.operationId()
            return try {
                PreparedOutbound(
                    contactId,
                    operationId,
                    delivery,
                    markCommitUncertain = markCommitUncertain,
                )
            } finally {
                contactId.fill(0)
                operationId.fill(0)
            }
        }

        fun fromPending(
            pending: PendingOutbound,
            delivery: ValidatedOutboundDelivery,
            markCommitUncertain: (ByteArray) -> Boolean,
        ): PreparedOutbound {
            verifyStoredCiphertext(pending.ciphertext.copyOf(), delivery)
            return PreparedOutbound(
                pending.contactId,
                pending.operationId,
                delivery,
                pending.state,
                markCommitUncertain,
            )
        }

        private fun verifyStoredCiphertext(
            stored: ByteArray,
            delivery: ValidatedOutboundDelivery,
        ) {
            var expected = ByteArray(0)
            try {
                expected = PendingCiphertextCodec.encode(delivery.parts, delivery.presentation)
                require(java.security.MessageDigest.isEqual(stored, expected)) {
                    "Committed outbound ciphertext mismatch"
                }
            } finally {
                stored.fill(0)
                expected.fill(0)
            }
        }
    }
}

internal class OutboundCommitBoundary(
    operationId: ByteArray,
    transition: (ByteArray) -> Boolean,
) : Closeable {
    private val attempted = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private var id = operationId.copyOf()
    private var transition: ((ByteArray) -> Boolean)? = transition

    fun markUncertain(): Boolean {
        if (closed.get() || !attempted.compareAndSet(false, true)) return false
        val operationId = id.copyOf()
        return try {
            transition?.invoke(operationId) == true
        } finally {
            operationId.fill(0)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        id.fill(0)
        id = ByteArray(0)
        transition = null
    }
}

/** Opaque validated ciphertext parts. It contains ciphertext and public routing metadata only. */
class ParsedInboundCiphertext internal constructor(
    routingTag: ByteArray,
    messageId: ByteArray,
    orderedParts: List<String>,
) : Closeable {
    private val closed = AtomicBoolean(false)
    internal val routingTag = routingTag.copyOf()
    internal val messageId = messageId.copyOf()
    private var parts: List<String> = orderedParts.toList()

    internal fun orderedParts(): List<String> {
        check(!closed.get()) { "Parsed ciphertext is closed" }
        return parts
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        routingTag.fill(0)
        messageId.fill(0)
        parts = emptyList()
    }

    override fun toString(): String = "ParsedInboundCiphertext(redacted)"
}

/**
 * Owns plaintext recovered from the encrypted pending-display record.
 *
 * [consumePlaintext] may be called once. The callback must not retain the supplied array. Android
 * text widgets necessarily create JVM-managed text copies, so callers must still clear their UI.
 */
class DecryptedMessage internal constructor(
    contactId: ByteArray,
    pendingDisplay: PendingDisplay,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val contact = contactId.copyOf()
    private val message = pendingDisplay.messageId.copyOf()
    private val pending = pendingDisplay

    fun contactId(): ByteArray = contact.copyOf()
    fun messageId(): ByteArray = message.copyOf()

    fun <T> consumePlaintext(block: (ByteArray) -> T): T {
        check(!closed.get()) { "Decrypted message is closed" }
        return pending.plaintext.consume(block)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        contact.fill(0)
        message.fill(0)
        pending.close()
    }

    override fun toString(): String = "DecryptedMessage(redacted)"
}

sealed interface VaultUnlockAction {
    val operation: VaultOperation

    data class Unlocked(
        override val operation: VaultOperation,
        val protectionInfo: KeyProtectionInfo,
    ) : VaultUnlockAction

    class AuthenticationRequired internal constructor(
        internal val delegate: VaultUnlockRequest.PromptAuthentication,
    ) : VaultUnlockAction {
        override val operation: VaultOperation = delegate.operation
        val allowedAuthenticators: Int = delegate.allowedAuthenticators
        val requiresLegacyConfirmCredential: Boolean = delegate.requiresLegacyConfirmCredential
        private val consumed = AtomicBoolean(false)

        internal fun consumeDelegate(): VaultUnlockRequest.PromptAuthentication {
            check(consumed.compareAndSet(false, true)) { "Unlock action was already completed" }
            return delegate
        }

        override fun toString(): String = "VaultUnlockAction.AuthenticationRequired"
    }

    /**
     * Authentication-per-use mode. [cryptoObject] is intentionally exposed as [Any] so the
     * runtime facade does not leak AndroidX Biometric into callers that use credential fallback.
     */
    class CryptoObjectAuthenticationRequired internal constructor(
        internal val delegate: VaultUnlockRequest.CryptoObjectAuthentication,
    ) : VaultUnlockAction {
        override val operation: VaultOperation = delegate.operation
        val allowedAuthenticators: Int = delegate.allowedAuthenticators
        val cryptoObject: Any = delegate.cryptoObject
        private val consumed = AtomicBoolean(false)

        internal fun consumeDelegate(): VaultUnlockRequest.CryptoObjectAuthentication {
            check(consumed.compareAndSet(false, true)) { "Unlock action was already completed" }
            return delegate
        }

        override fun toString(): String = "VaultUnlockAction.CryptoObjectAuthenticationRequired"
    }

    data class KeyInvalidated(
        override val operation: VaultOperation,
    ) : VaultUnlockAction
}

enum class SecureRuntimeError {
    OWNER_CREATION_CONFLICT,
    CONTACT_NOT_FOUND,
    CONTACT_NOT_READY,
    CONTACT_REVISION_CONFLICT,
    RATCHET_NOT_FOUND,
    RATCHET_REVISION_CONFLICT,
    WRONG_CONTACT,
    REPLAY,
    INVALID_PARTS,
    UNSUPPORTED_VERSION,
    MISSING_PART,
    INCONSISTENT_PARTS,
    TOO_MANY_PARTS,
    PENDING_DISPLAY_NOT_FOUND,
    CORRUPT_STATE,
}

class SecureRuntimeException(
    val reason: SecureRuntimeError,
    cause: Throwable? = null,
) : IllegalStateException("CipherBoard runtime error: ${reason.name}", cause)
