// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.OwnedSecret
import org.cipherboard.pairing.PairingQrPayload
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/** Public, non-secret QR offer plus the opaque identifier needed to cancel it. */
class PairingOffer internal constructor(
    val qrPayload: PairingQrPayload,
    pairingId: ByteArray,
    val expiresAtEpochMillis: Long,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val id = pairingId.copyOf()

    fun pairingId(): ByteArray {
        check(!closed.get()) { "Pairing offer is closed" }
        return id.copyOf()
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) id.fill(0)
    }

    override fun toString(): String = "PairingOffer(redacted)"
}

/**
 * Responder-side QR and verification representations.
 *
 * The Olm session is not held by this object. It is already inside the encrypted pending-pairing
 * Vault record, so closing or recreating an Activity cannot expose it through saved state.
 */
class PairingResponse internal constructor(
    val qrPayload: PairingQrPayload,
    pairingId: ByteArray,
    remoteFingerprint: ByteArray,
    previousRemoteFingerprint: ByteArray,
    val safetyNumber: String,
    val safetyCode: String,
    val expiresAtEpochMillis: Long,
    internal val expectedPendingRevision: Long,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val id = pairingId.copyOf()
    private val fingerprint = remoteFingerprint.copyOf()
    private val previousFingerprint = previousRemoteFingerprint.copyOf()
    val identityChanged: Boolean = previousFingerprint.isNotEmpty() &&
        !previousFingerprint.contentEquals(fingerprint)

    init {
        require(previousFingerprint.isEmpty() || previousFingerprint.size == fingerprint.size)
    }

    fun pairingId(): ByteArray {
        check(!closed.get()) { "Pairing response is closed" }
        return id.copyOf()
    }

    fun remoteFingerprint(): ByteArray {
        check(!closed.get()) { "Pairing response is closed" }
        return fingerprint.copyOf()
    }

    fun previousRemoteFingerprint(): ByteArray {
        check(!closed.get()) { "Pairing response is closed" }
        return previousFingerprint.copyOf()
    }

    internal fun requireOpen() = check(!closed.get()) { "Pairing response is closed" }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        id.fill(0)
        fingerprint.fill(0)
        previousFingerprint.fill(0)
    }

    override fun toString(): String = "PairingResponse(redacted)"
}

/**
 * Offerer-side pairing result awaiting an in-person Safety Number confirmation.
 *
 * Updated account and Olm session state exist only in these zeroizing owners until [confirmPairing]
 * commits them. Do not put this object in saved state or an Intent.
 */
class PreparedPairingConfirmation internal constructor(
    pairingId: ByteArray,
    contactId: ByteArray,
    remoteFingerprint: ByteArray,
    previousRemoteFingerprint: ByteArray,
    routingTag: ByteArray,
    val safetyNumber: String,
    val safetyCode: String,
    val expiresAtEpochMillis: Long,
    internal val expectedPendingRevision: Long,
    internal val expectedOwnerRevision: Long,
    internal val localContactName: String,
    internal val replacingExistingContact: Boolean,
    internal val protocolVersion: Int,
    internal val ownerLocalName: String,
    ownerFingerprint: ByteArray,
    internal val ownerCreatedAtEpochMillis: Long,
    internal val updatedAccountState: OwnedSecret,
    internal val initialSessionState: OwnedSecret,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val consumed = AtomicBoolean(false)
    private val pairing = pairingId.copyOf()
    private val contact = contactId.copyOf()
    private val fingerprint = remoteFingerprint.copyOf()
    private val previousFingerprint = previousRemoteFingerprint.copyOf()
    private val tag = routingTag.copyOf()
    private val localFingerprint = ownerFingerprint.copyOf()
    val identityChanged: Boolean = previousFingerprint.isNotEmpty() &&
        !previousFingerprint.contentEquals(fingerprint)

    init {
        require(previousFingerprint.isEmpty() || previousFingerprint.size == fingerprint.size)
    }

    fun pairingId(): ByteArray {
        requireOpen()
        return pairing.copyOf()
    }

    fun remoteFingerprint(): ByteArray {
        requireOpen()
        return fingerprint.copyOf()
    }

    fun previousRemoteFingerprint(): ByteArray {
        requireOpen()
        return previousFingerprint.copyOf()
    }

    internal fun contactId(): ByteArray {
        requireOpen()
        return contact.copyOf()
    }

    internal fun routingTag(): ByteArray {
        requireOpen()
        return tag.copyOf()
    }

    internal fun ownerFingerprint(): ByteArray {
        requireOpen()
        return localFingerprint.copyOf()
    }

    internal fun consumeOnce() {
        requireOpen()
        check(consumed.compareAndSet(false, true)) { "Pairing confirmation was already consumed" }
    }

    private fun requireOpen() = check(!closed.get()) { "Pairing confirmation is closed" }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        pairing.fill(0)
        contact.fill(0)
        fingerprint.fill(0)
        previousFingerprint.fill(0)
        tag.fill(0)
        localFingerprint.fill(0)
        updatedAccountState.close()
        initialSessionState.close()
    }

    override fun toString(): String = "PreparedPairingConfirmation(redacted)"
}

enum class PairingRuntimeError {
    OWNER_REQUIRED,
    INVALID_QR,
    WRONG_QR_TYPE,
    EXPIRED,
    NOT_FOUND,
    ALREADY_USED,
    STATE_CONFLICT,
    TRANSCRIPT_MISMATCH,
    CONTACT_ALREADY_EXISTS,
    CONTACT_ID_COLLISION,
    CORRUPT_PENDING_STATE,
}

class PairingRuntimeException(
    val reason: PairingRuntimeError,
    cause: Throwable? = null,
) : IllegalStateException("CipherBoard pairing error: ${reason.name}", cause)
