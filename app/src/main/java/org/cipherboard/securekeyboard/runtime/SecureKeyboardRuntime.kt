// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.app.Application
import androidx.biometric.BiometricPrompt
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.CryptoCoreException
import org.cipherboard.cryptocore.CryptoErrorCode
import org.cipherboard.cryptocore.EnvelopeMetadata
import org.cipherboard.cryptocore.OwnedSecret as CryptoOwnedSecret
import org.cipherboard.cryptocore.TransportMode
import org.cipherboard.pairing.PairingQrPayload
import org.cipherboard.securestorage.AndroidVaultKeyManager
import org.cipherboard.securestorage.AtomicInboundResult
import org.cipherboard.securestorage.ContactVaultEntry
import org.cipherboard.securestorage.ContactVaultRepository
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.OwnerIdentityAccountState
import org.cipherboard.securestorage.OwnedSecret as StorageOwnedSecret
import org.cipherboard.securestorage.RatchetRevisionConflictException
import org.cipherboard.securestorage.VaultAuthenticationMode
import org.cipherboard.securestorage.VaultCorruptException
import org.cipherboard.securestorage.VaultLockController
import org.cipherboard.securestorage.VaultLockPolicy
import org.cipherboard.securestorage.VaultRecordStore
import org.cipherboard.securestorage.VaultUnlockRequest
import java.io.Closeable
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Process-local facade joining the native crypto core to crash-safe encrypted storage.
 *
 * This class has no API that persists plaintext. Encryption publishes ciphertext only after the
 * new ratchet and pending outbound record commit atomically. Decryption returns plaintext only by
 * reopening the encrypted pending-display record after the inbound transaction commits.
 */
class SecureKeyboardRuntime private constructor(
    application: Application,
    private val crypto: CipherBoardCrypto = CipherBoardCrypto(),
    private val lockController: VaultLockController = VaultLockController(),
    private val keyManager: AndroidVaultKeyManager = AndroidVaultKeyManager(application),
    private val recordStore: VaultRecordStore = VaultRecordStore(application, lockController),
    private val contacts: ContactVaultRepository = ContactVaultRepository(recordStore),
    private val clock: EpochMillisSource = SystemEpochMillisSource,
) : Closeable, SecureRuntimeLifecycleTarget {
    private val operationLock = ReentrantLock()
    @Volatile private var secureImeForeground = false
    private var keyInvalidationObserved = false
    private val lifecycle = SecureRuntimeLifecycle(application, this)
    private val pairing = PairingRuntimeCoordinator(
        NativePairingCrypto(crypto),
        RepositoryPairingVault(contacts),
        clock,
        SecurePairingRandomSource(),
    )

    init {
        lockController.onBootBoundary()
        purgeExpiredPendingDisplays()
        lifecycle.register()
    }

    val isVaultUnlocked: Boolean
        get() = lockController.isUnlocked()

    val isUnlocked: Boolean
        get() = isVaultUnlocked

    var lockPolicy: VaultLockPolicy
        get() = lockController.policy
        set(value) {
            lockController.policy = value
        }

    fun prepareUnlock(
        mode: VaultAuthenticationMode = VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
    ): VaultUnlockAction = operationLock.withLock {
        mapUnlockRequest(
            keyManager.prepareUnlock(
                requestedMode = mode,
                forceFreshAuthentication = lockController.requiresFreshAuthentication(),
            ),
        )
    }

    /** Call only after the authentication UI represented by [action] reports success. */
    fun completePromptAuthentication(
        action: VaultUnlockAction.AuthenticationRequired,
    ): VaultUnlockAction = operationLock.withLock {
        mapUnlockRequest(keyManager.completePromptAuthentication(action.consumeDelegate()))
    }

    /** Call only after BiometricPrompt authenticates [VaultUnlockAction.cryptoObject]. */
    fun completeCryptoObjectAuthentication(
        action: VaultUnlockAction.CryptoObjectAuthenticationRequired,
        authenticatedCryptoObject: Any,
    ): VaultUnlockAction = operationLock.withLock {
        val request = action.consumeDelegate()
        val result = authenticatedCryptoObject as? BiometricPrompt.CryptoObject
            ?: throw IllegalArgumentException("Authentication returned an invalid CryptoObject")
        mapUnlockRequest(keyManager.completeCryptoObjectAuthentication(request, result))
    }

    override fun lockVault() = lockController.lock()
    override fun onBackgrounded() = lockController.onBackgrounded()
    override fun onForegrounded(): Boolean = lockController.onForegrounded()
    fun onSecureImeForegrounded(): Boolean {
        secureImeForeground = true
        return lockController.onForegrounded()
    }
    fun onSecureImeBackgrounded() {
        secureImeForeground = false
        lockController.onBackgrounded()
    }
    override val isSecureImeForeground: Boolean
        get() = secureImeForeground
    override fun lockIfExpired(): Boolean = lockController.lockIfExpired()

    /** Irreversibly clears an unreadable Vault after Android Keystore invalidation was observed. */
    fun resetInvalidatedVault() = operationLock.withLock {
        check(keyInvalidationObserved) { "Vault reset requires a detected Keystore invalidation" }
        lockController.onKeystoreInvalidated()
        // Delete encrypted records first. A crash at any later point cannot restore old ratchets.
        recordStore.destroyAll()
        keyManager.destroyWrappedKeyMaterial()
        keyInvalidationObserved = false
    }

    fun ensureOwner(localName: String): OwnerIdentitySummary = operationLock.withLock {
        contacts.readOwnerAccount()?.use { return@withLock it.value.toSummary() }

        val protocolVersion = crypto.protocolVersions().cipherBoard
        val created = crypto.createAccount()
        try {
            val ownerState = created.accountState.use { accountBytes ->
                OwnerIdentityAccountState(
                    localOwnerName = localName,
                    accountState = accountBytes,
                    identityFingerprint = created.fingerprint,
                    protocolVersion = protocolVersion,
                    createdAtEpochMillis = clock.nowEpochMillis(),
                )
            }
            ownerState.use { state ->
                if (!contacts.createOwnerAccount(state)) {
                    throw SecureRuntimeException(SecureRuntimeError.OWNER_CREATION_CONFLICT)
                }
                state.toSummary()
            }
        } finally {
            created.accountState.close()
            created.fingerprint.fill(0)
            created.identity.curve25519.fill(0)
            created.identity.ed25519.fill(0)
        }
    }

    fun owner(): OwnerIdentitySummary? = operationLock.withLock {
        contacts.readOwnerAccount()?.use { it.value.toSummary() }
    }

    fun listContacts(): List<SecureContactSummary> = operationLock.withLock {
        contacts.listContacts().map { record -> record.use { it.value.toSummary() } }
    }

    fun contact(contactId: ByteArray): SecureContactSummary? = operationLock.withLock {
        contacts.readContact(contactId)?.use { it.value.toSummary() }
    }

    fun createPairingOffer(
        localContactName: String,
        ttlSeconds: Long = 300,
        capabilities: Long = 0,
    ): PairingOffer = operationLock.withLock {
        pairing.createOffer(localContactName, ttlSeconds, capabilities)
    }

    fun respondToPairingOffer(
        localContactName: String,
        offerQr: PairingQrPayload,
        capabilities: Long = 0,
    ): PairingResponse = operationLock.withLock {
        pairing.respondToOffer(localContactName, offerQr, capabilities)
    }

    /** Starts offerer-side re-pairing without changing the contact's local name or identifier. */
    fun createRepairingOffer(
        contactId: ByteArray,
        ttlSeconds: Long = 300,
        capabilities: Long = 0,
    ): PairingOffer = operationLock.withLock {
        val id = contactId.copyOf()
        try {
            val existing = contacts.readContact(id)
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
            existing.use {
                if (!it.value.requiresRepairing) {
                    throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_READY)
                }
                pairing.createOffer(it.value.localName, ttlSeconds, capabilities, id)
            }
        } finally {
            id.fill(0)
        }
    }

    /** Starts responder-side re-pairing for a contact whose old session was destroyed. */
    fun respondToPairingOfferForContact(
        contactId: ByteArray,
        offerQr: PairingQrPayload,
        capabilities: Long = 0,
    ): PairingResponse = operationLock.withLock {
        val id = contactId.copyOf()
        try {
            val existing = contacts.readContact(id)
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
            existing.use {
                if (!it.value.requiresRepairing) {
                    throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_READY)
                }
                pairing.respondToOffer(it.value.localName, offerQr, capabilities, id)
            }
        } finally {
            id.fill(0)
        }
    }

    fun preparePairingResponse(
        responseQr: PairingQrPayload,
    ): PreparedPairingConfirmation = operationLock.withLock {
        pairing.prepareResponse(responseQr)
    }

    /** Consumes and closes [prepared] whether the atomic commit succeeds or fails. */
    fun confirmPairing(prepared: PreparedPairingConfirmation): SecureContactSummary =
        operationLock.withLock { pairing.confirm(prepared) }

    /** Consumes and closes responder-side [response] after the atomic commit attempt. */
    fun confirmPairing(response: PairingResponse): SecureContactSummary =
        operationLock.withLock { pairing.confirm(response) }

    fun cancelPairing(pairingId: ByteArray): Boolean = operationLock.withLock {
        val id = pairingId.copyOf()
        try {
            pairing.cancel(id)
        } finally {
            id.fill(0)
        }
    }

    /** Cancels or expires every bounded, discoverable ACTIVE pairing before a new UI flow starts. */
    fun cancelActivePairings(): Int = operationLock.withLock {
        pairing.cancelActivePairings()
    }

    fun renameContact(contactId: ByteArray, localName: String): SecureContactSummary =
        operationLock.withLock {
            val id = contactId.copyOf()
            try {
                val current = contacts.readContact(id)
                    ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
                current.use {
                    if (!contacts.renameContact(id, it.revision, localName)) {
                        throw SecureRuntimeException(SecureRuntimeError.CONTACT_REVISION_CONFLICT)
                    }
                }
                contacts.readContact(id)?.use { it.value.toSummary() }
                    ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
            } finally {
                id.fill(0)
            }
        }

    /** Verifies a healthy session, including a freshly re-paired identity change after comparison. */
    fun verifyContact(
        contactId: ByteArray,
        expectedFingerprint: String,
        expectedSafetyNumber: String,
        expectedSafetyCode: String,
    ): SecureContactSummary = operationLock.withLock {
        val id = contactId.copyOf()
        try {
            val current = contacts.readContact(id)
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
            current.use {
                if (!verificationSnapshotMatches(
                        it.value.remoteIdentityFingerprint,
                        it.value.safetyNumber,
                        it.value.safetyCode,
                        expectedFingerprint,
                        expectedSafetyNumber,
                        expectedSafetyCode,
                    )
                ) {
                    throw SecureRuntimeException(SecureRuntimeError.CONTACT_REVISION_CONFLICT)
                }
                if (it.value.verificationStatus == ContactVerificationStatus.VERIFIED) {
                    return@withLock it.value.toSummary()
                }
                val canVerifyUnverified = it.value.verificationStatus == ContactVerificationStatus.UNVERIFIED &&
                    !it.value.requiresRepairing && !it.value.sessionError && !it.value.keyChanged
                val canVerifyReplacement = it.value.verificationStatus == ContactVerificationStatus.KEY_CHANGED &&
                    !it.value.requiresRepairing && !it.value.sessionError && it.value.keyChanged
                if (!canVerifyUnverified && !canVerifyReplacement) {
                    throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_READY)
                }
                if (canVerifyReplacement) {
                    recordStore.readRatchet(id)?.close()
                        ?: throw SecureRuntimeException(SecureRuntimeError.RATCHET_NOT_FOUND)
                }
                if (!contacts.updateContactStatus(
                        contactId = id,
                        expectedRevision = it.revision,
                        verificationStatus = ContactVerificationStatus.VERIFIED,
                        requiresRepairing = false,
                        sessionError = false,
                        keyChanged = false,
                        lastActiveAtEpochMillis = maxOf(
                            clock.nowEpochMillis(),
                            it.value.lastActiveAtEpochMillis,
                        ),
                    )
                ) {
                    throw SecureRuntimeException(SecureRuntimeError.CONTACT_REVISION_CONFLICT)
                }
            }
            contacts.readContact(id)?.use { it.value.toSummary() }
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
        } finally {
            id.fill(0)
        }
    }

    /** Atomically deletes the ratchet and message artifacts, then requires explicit re-pairing. */
    fun destroyContactSession(contactId: ByteArray): SecureContactSummary = operationLock.withLock {
        val id = contactId.copyOf()
        try {
            val current = contacts.readContact(id)
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
            current.use { contactRecord ->
                val ratchet = recordStore.readRatchet(id)
                if (ratchet == null) {
                    if (contactRecord.value.requiresRepairing &&
                        contactRecord.value.verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED
                    ) {
                        return@withLock contactRecord.value.toSummary()
                    }
                    throw SecureRuntimeException(SecureRuntimeError.RATCHET_NOT_FOUND)
                }
                ratchet.use {
                    if (!contacts.destroyContactSession(
                            contactId = id,
                            expectedRevision = contactRecord.revision,
                            expectedRatchetRevision = it.revision,
                            lastActiveAtEpochMillis = maxOf(
                                clock.nowEpochMillis(),
                                contactRecord.value.lastActiveAtEpochMillis,
                            ),
                        )
                    ) {
                        throw SecureRuntimeException(SecureRuntimeError.CONTACT_REVISION_CONFLICT)
                    }
                }
            }
            contacts.readContact(id)?.use { it.value.toSummary() }
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
        } finally {
            id.fill(0)
        }
    }

    /** Deletes contact metadata and cascades ratchet, pending message, and replay records. */
    fun deleteContact(contactId: ByteArray): Boolean = operationLock.withLock {
        val id = contactId.copyOf()
        try {
            val current = contacts.readContact(id) ?: return@withLock false
            current.use { contacts.deleteContact(id, it.revision) }
        } finally {
            id.fill(0)
        }
    }

    /**
     * Consumes and overwrites [plaintext]. The caller must not read or reuse that array afterward.
     */
    fun encrypt(
        contactId: ByteArray,
        plaintext: ByteArray,
        mode: TransportMode = TransportMode.UNIVERSAL,
        capabilities: Long = 0,
    ): PreparedOutbound = operationLock.withLock {
        val plaintextSecret = CryptoOwnedSecret.takeOwnership(plaintext)
        try {
            val contact = contacts.readContact(contactId)
                ?: throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_FOUND)
            val contactRevisionAndActivity = contact.use {
                requireUsableContact(it.value)
                it.revision to it.value.lastActiveAtEpochMillis
            }
            try {
                val current = recordStore.readRatchet(contactId)
                    ?: throw SecureRuntimeException(SecureRuntimeError.RATCHET_NOT_FOUND)
                current.use { ratchet ->
                    val encrypted = ratchet.secret.consume { stateBytes ->
                        val state = CryptoOwnedSecret.takeOwnership(stateBytes)
                        try {
                            crypto.encrypt(state, plaintextSecret, capabilities, mode)
                        } finally {
                            state.close()
                        }
                    }
                    try {
                        val pendingBytes = PendingCiphertextCodec.encode(encrypted.parts)
                        try {
                            val nextState = encrypted.sessionState.use { state ->
                                StorageOwnedSecret.takeOwnership(state.copyOf())
                            }
                            try {
                                contacts.commitOutbound(
                                    contactId = contactId,
                                    expectedContactRevision = contactRevisionAndActivity.first,
                                    lastActiveAtEpochMillis = maxOf(
                                        clock.nowEpochMillis(),
                                        contactRevisionAndActivity.second,
                                    ),
                                    expectedRatchetRevision = ratchet.revision,
                                    ratchetSchemaVersion = ratchet.schemaVersion,
                                    newRatchetState = nextState,
                                    operationId = encrypted.messageId,
                                    pendingCiphertext = pendingBytes,
                                )
                            } catch (error: RatchetRevisionConflictException) {
                                throw SecureRuntimeException(SecureRuntimeError.RATCHET_REVISION_CONFLICT, error)
                            } finally {
                                nextState.close()
                            }
                        } finally {
                            pendingBytes.fill(0)
                        }
                        PreparedOutbound(
                            contactId,
                            encrypted.messageId,
                            encrypted.parts.toList(),
                            markCommitUncertain = ::markOutboundCommitUncertain,
                        )
                    } finally {
                        encrypted.sessionState.close()
                        encrypted.messageId.fill(0)
                    }
                }
            } catch (error: Throwable) {
                throw localSessionFailure(
                    contactId,
                    contactRevisionAndActivity.first,
                    contactRevisionAndActivity.second,
                    error,
                )
            }
        } finally {
            plaintextSecret.close()
        }
    }

    fun completeOutbound(operationId: ByteArray): Boolean = operationLock.withLock {
        recordStore.completeOutbound(operationId)
    }

    /** Must succeed before any ciphertext is handed to an external InputConnection. */
    fun markOutboundCommitUncertain(operationId: ByteArray): Boolean = operationLock.withLock {
        recordStore.markOutboundCommitUncertain(operationId)
    }

    /** Returns ciphertext-only operations, including uncertain records that must not be retried. */
    fun pendingOutbound(): List<PreparedOutbound> = operationLock.withLock {
        recordStore.listPendingOutbound().map { pending ->
            try {
                PreparedOutbound(
                    pending.contactId,
                    pending.operationId,
                    PendingCiphertextCodec.decode(pending.ciphertext),
                    pending.state,
                    ::markOutboundCommitUncertain,
                )
            } catch (error: IllegalArgumentException) {
                throw SecureRuntimeException(SecureRuntimeError.CORRUPT_STATE, error)
            } finally {
                pending.operationId.fill(0)
                pending.contactId.fill(0)
                pending.ciphertext.fill(0)
            }
        }
    }

    fun parseCiphertext(parts: List<String>): ParsedInboundCiphertext = operationLock.withLock {
        parseAndOrderParts(parts)
    }

    fun decrypt(parts: List<String>): DecryptedMessage = parseCiphertext(parts).use(::decrypt)

    fun decrypt(parsed: ParsedInboundCiphertext): DecryptedMessage = operationLock.withLock {
        purgeExpiredPendingDisplays()
        parsed.let {
            val match = findContactByRoutingTag(it.routingTag)
                ?: throw SecureRuntimeException(SecureRuntimeError.WRONG_CONTACT)
            match.use { contact ->
                requireUsableContact(contact)
                try {
                    val ciphertextDigest = digestCiphertextParts(it.orderedParts())
                    try {
                        if (recordStore.isReplay(contact.contactId, it.messageId)) {
                            val pending = recordStore.readPendingDisplay(contact.contactId, it.messageId)
                                ?: throw SecureRuntimeException(SecureRuntimeError.REPLAY)
                            if (!MessageDigest.isEqual(pending.ciphertextDigest, ciphertextDigest)) {
                                pending.close()
                                throw SecureRuntimeException(SecureRuntimeError.REPLAY)
                            }
                            return@withLock DecryptedMessage(contact.contactId, pending)
                        }
                        val current = recordStore.readRatchet(contact.contactId)
                            ?: throw SecureRuntimeException(SecureRuntimeError.RATCHET_NOT_FOUND)
                        current.use { ratchet ->
                            val decrypted = ratchet.secret.consume { stateBytes ->
                                val state = CryptoOwnedSecret.takeOwnership(stateBytes)
                                try {
                                    crypto.decrypt(state, it.orderedParts())
                                } finally {
                                    state.close()
                                }
                            }
                            try {
                                if (!decrypted.messageId.contentEquals(it.messageId)) {
                                    throw SecureRuntimeException(SecureRuntimeError.INVALID_PARTS)
                                }
                                val nextState = decrypted.sessionState.use { state ->
                                    StorageOwnedSecret.takeOwnership(state.copyOf())
                                }
                                val result = try {
                                    val pendingPlaintext = decrypted.plaintext.use { plaintext ->
                                        StorageOwnedSecret.takeOwnership(plaintext.copyOf())
                                    }
                                    try {
                                        contacts.commitInbound(
                                            contactId = contact.contactId,
                                            expectedContactRevision = contact.revision,
                                            lastActiveAtEpochMillis = maxOf(
                                                clock.nowEpochMillis(),
                                                contact.lastActiveAtEpochMillis,
                                            ),
                                            expectedRatchetRevision = ratchet.revision,
                                            ratchetSchemaVersion = ratchet.schemaVersion,
                                            newRatchetState = nextState,
                                            messageId = decrypted.messageId,
                                            ciphertextDigest = ciphertextDigest,
                                            pendingPlaintext = pendingPlaintext,
                                        )
                                    } finally {
                                        pendingPlaintext.close()
                                    }
                                } finally {
                                    nextState.close()
                                }
                                when (result) {
                                    AtomicInboundResult.REPLAY ->
                                        throw SecureRuntimeException(SecureRuntimeError.REPLAY)
                                    AtomicInboundResult.REVISION_CONFLICT ->
                                        throw SecureRuntimeException(SecureRuntimeError.RATCHET_REVISION_CONFLICT)
                                    AtomicInboundResult.COMMITTED -> Unit
                                }
                                val pending = recordStore.readPendingDisplay(
                                    contact.contactId,
                                    decrypted.messageId,
                                ) ?: throw SecureRuntimeException(SecureRuntimeError.PENDING_DISPLAY_NOT_FOUND)
                                DecryptedMessage(contact.contactId, pending)
                            } finally {
                                decrypted.sessionState.close()
                                decrypted.plaintext.close()
                                decrypted.messageId.fill(0)
                            }
                        }
                    } finally {
                        ciphertextDigest.fill(0)
                    }
                } catch (error: Throwable) {
                    throw localSessionFailure(
                        contact.contactId,
                        contact.revision,
                        contact.lastActiveAtEpochMillis,
                        error,
                    )
                }
            }
        }
    }

    fun discardPendingDisplay(messageId: ByteArray): Boolean = operationLock.withLock {
        recordStore.deletePendingDisplay(messageId)
    }

    private fun purgeExpiredPendingDisplays() {
        val now = clock.nowEpochMillis().coerceAtLeast(0)
        val cutoff = (now - PENDING_DISPLAY_CRASH_RECOVERY_MILLIS).coerceAtLeast(0)
        recordStore.purgePendingDisplaysCreatedAtOrBefore(cutoff)
    }

    override fun close() {
        operationLock.withLock {
            lockController.close()
            recordStore.close()
        }
    }

    private fun mapUnlockRequest(request: VaultUnlockRequest): VaultUnlockAction = when (request) {
        is VaultUnlockRequest.Unlocked -> {
            keyInvalidationObserved = false
            val info = request.material.protectionInfo
            lockController.unlock(request.material)
            request.material.close()
            VaultUnlockAction.Unlocked(request.operation, info)
        }
        is VaultUnlockRequest.PromptAuthentication ->
            VaultUnlockAction.AuthenticationRequired(request)
        is VaultUnlockRequest.CryptoObjectAuthentication ->
            VaultUnlockAction.CryptoObjectAuthenticationRequired(request)
        is VaultUnlockRequest.KeyInvalidated -> {
            keyInvalidationObserved = true
            lockController.onKeystoreInvalidated()
            VaultUnlockAction.KeyInvalidated(request.operation)
        }
    }

    private fun digestCiphertextParts(parts: List<String>): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(parts.size).array())
        parts.forEach { part ->
            val bytes = part.toByteArray(Charsets.UTF_8)
            try {
                digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
                digest.update(bytes)
            } finally {
                bytes.fill(0)
            }
        }
        return digest.digest()
    }

    private fun parseAndOrderParts(parts: List<String>): ParsedInboundCiphertext {
        if (parts.isEmpty() || parts.size > MAX_PARTS) {
            throw SecureRuntimeException(
                if (parts.size > MAX_PARTS) SecureRuntimeError.TOO_MANY_PARTS
                else SecureRuntimeError.MISSING_PART,
            )
        }
        val metadata = ArrayList<EnvelopeMetadata>(parts.size)
        try {
            parts.forEach { metadata += crypto.parseEnvelope(it) }
            val first = metadata.first()
            if (first.totalParts != parts.size ||
                metadata.any {
                    it.totalParts != first.totalParts ||
                        !it.messageId.contentEquals(first.messageId) ||
                        !it.routingTag.contentEquals(first.routingTag)
                }
            ) {
                throw SecureRuntimeException(SecureRuntimeError.INCONSISTENT_PARTS)
            }
            val byNumber = metadata.indices.associateBy { metadata[it].partNumber }
            if (byNumber.size != parts.size) {
                throw SecureRuntimeException(SecureRuntimeError.INCONSISTENT_PARTS)
            }
            if ((1..parts.size).any { it !in byNumber }) {
                throw SecureRuntimeException(SecureRuntimeError.MISSING_PART)
            }
            return ParsedInboundCiphertext(
                routingTag = first.routingTag,
                messageId = first.messageId,
                orderedParts = (1..parts.size).map { parts.getValue(byNumber.getValue(it)) },
            )
        } catch (error: SecureRuntimeException) {
            throw error
        } catch (error: CryptoCoreException) {
            throw SecureRuntimeException(error.reason.toRuntimeParseError(), error)
        } catch (error: RuntimeException) {
            throw SecureRuntimeException(SecureRuntimeError.INVALID_PARTS, error)
        } finally {
            metadata.forEach {
                it.routingTag.fill(0)
                it.messageId.fill(0)
            }
        }
    }

    private fun findContactByRoutingTag(routingTag: ByteArray): ContactMatch? {
        var match: ContactMatch? = null
        val allContacts = contacts.listContacts()
        try {
            allContacts.forEach { record ->
                val entry = record.value
                if (entry.remoteSessionTag.contentEquals(routingTag)) {
                    if (match != null) {
                        match.close()
                        throw SecureRuntimeException(SecureRuntimeError.CORRUPT_STATE)
                    }
                    match = ContactMatch(
                        contactId = entry.internalId,
                        revision = record.revision,
                        lastActiveAtEpochMillis = entry.lastActiveAtEpochMillis,
                        verificationStatus = entry.verificationStatus,
                        requiresRepairing = entry.requiresRepairing,
                        sessionError = entry.sessionError,
                        keyChanged = entry.keyChanged,
                    )
                }
            }
            return match
        } finally {
            allContacts.forEach { it.close() }
        }
    }

    private fun requireUsableContact(contact: ContactVaultEntry) {
        requireUsableContact(
            contact.verificationStatus,
            contact.requiresRepairing,
            contact.sessionError,
            contact.keyChanged,
        )
    }

    private fun requireUsableContact(match: ContactMatch) {
        requireUsableContact(
            match.verificationStatus,
            match.requiresRepairing,
            match.sessionError,
            match.keyChanged,
        )
    }

    private fun requireUsableContact(
        verificationStatus: ContactVerificationStatus,
        requiresRepairing: Boolean,
        sessionError: Boolean,
        keyChanged: Boolean,
    ) {
        if (requiresRepairing || sessionError || keyChanged ||
            verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED
        ) {
            throw SecureRuntimeException(SecureRuntimeError.CONTACT_NOT_READY)
        }
    }

    private fun localSessionFailure(
        contactId: ByteArray,
        contactRevision: Long,
        lastActiveAtEpochMillis: Long,
        error: Throwable,
    ): Throwable = mapLocalSessionFailure(
        error = error,
        lastActiveAtEpochMillis = lastActiveAtEpochMillis,
        nowEpochMillis = clock.nowEpochMillis(),
    ) { activity ->
        contacts.updateContactStatus(
            contactId = contactId,
            expectedRevision = contactRevision,
            verificationStatus = ContactVerificationStatus.SESSION_ERROR,
            requiresRepairing = true,
            sessionError = true,
            keyChanged = false,
            lastActiveAtEpochMillis = activity,
        )
    }

    private fun OwnerIdentityAccountState.toSummary() = OwnerIdentitySummary(
        localOwnerName,
        identityFingerprint,
        protocolVersion,
        createdAtEpochMillis,
    )

    private fun ContactVaultEntry.toSummary() = SecureContactSummary(
        internalId,
        localName,
        remoteIdentityFingerprint,
        remoteSessionTag,
        verificationStatus,
        pairedAtEpochMillis,
        lastActiveAtEpochMillis,
        protocolVersion,
        safetyNumber,
        safetyCode,
        requiresRepairing,
        sessionError,
        keyChanged,
    )

    private class ContactMatch(
        contactId: ByteArray,
        val revision: Long,
        val lastActiveAtEpochMillis: Long,
        val verificationStatus: ContactVerificationStatus,
        val requiresRepairing: Boolean,
        val sessionError: Boolean,
        val keyChanged: Boolean,
    ) : Closeable {
        val contactId = contactId.copyOf()

        override fun close() {
            contactId.fill(0)
        }
    }

    companion object {
        private const val MAX_PARTS = 128
        private const val PENDING_DISPLAY_CRASH_RECOVERY_MILLIS = 5 * 60_000L

        @Volatile
        private var instance: SecureKeyboardRuntime? = null

        fun initialize(application: Application): SecureKeyboardRuntime =
            instance ?: synchronized(this) {
                instance ?: SecureKeyboardRuntime(application).also { instance = it }
            }

        fun get(): SecureKeyboardRuntime = checkNotNull(instance) {
            "SecureKeyboardRuntime has not been initialized"
        }
    }
}

internal fun mapLocalSessionFailure(
    error: Throwable,
    lastActiveAtEpochMillis: Long,
    nowEpochMillis: Long,
    markSessionError: (lastActiveAtEpochMillis: Long) -> Boolean,
): Throwable {
    val localStateCorrupt = error is VaultCorruptException ||
        (error is CryptoCoreException && error.reason == CryptoErrorCode.INVALID_STATE)
    if (!localStateCorrupt) return error
    val marked = markSessionError(maxOf(nowEpochMillis, lastActiveAtEpochMillis))
    return SecureRuntimeException(
        if (marked) SecureRuntimeError.CORRUPT_STATE else SecureRuntimeError.CONTACT_REVISION_CONFLICT,
        error,
    )
}

internal fun verificationSnapshotMatches(
    currentFingerprint: ByteArray,
    currentSafetyNumber: String,
    currentSafetyCode: String,
    expectedFingerprint: String,
    expectedSafetyNumber: String,
    expectedSafetyCode: String,
): Boolean {
    val formatted = CharArray(currentFingerprint.size * 2 + (currentFingerprint.size * 2 - 1) / 8)
    var output = 0
    currentFingerprint.forEachIndexed { index, value ->
        if (index > 0 && index * 2 % 8 == 0) formatted[output++] = ' '
        val unsigned = value.toInt() and 0xff
        formatted[output++] = FINGERPRINT_HEX[unsigned ushr 4]
        formatted[output++] = FINGERPRINT_HEX[unsigned and 0x0f]
    }
    return try {
        formatted.concatToString(0, output) == expectedFingerprint &&
            currentSafetyNumber == expectedSafetyNumber && currentSafetyCode == expectedSafetyCode
    } finally {
        formatted.fill('\u0000')
    }
}

private const val FINGERPRINT_HEX = "0123456789ABCDEF"

private fun <T> List<T>.getValue(index: Int): T = get(index)

private fun CryptoErrorCode.toRuntimeParseError(): SecureRuntimeError = when (this) {
    CryptoErrorCode.UNSUPPORTED_VERSION -> SecureRuntimeError.UNSUPPORTED_VERSION
    CryptoErrorCode.MISSING_PART -> SecureRuntimeError.MISSING_PART
    CryptoErrorCode.INCONSISTENT_PARTS -> SecureRuntimeError.INCONSISTENT_PARTS
    CryptoErrorCode.TOO_MANY_PARTS -> SecureRuntimeError.TOO_MANY_PARTS
    else -> SecureRuntimeError.INVALID_PARTS
}
