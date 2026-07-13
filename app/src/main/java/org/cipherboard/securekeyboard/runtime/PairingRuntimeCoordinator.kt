// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.CryptoCoreException
import org.cipherboard.cryptocore.CryptoErrorCode
import org.cipherboard.cryptocore.OfferCreated
import org.cipherboard.cryptocore.OwnedSecret as CryptoOwnedSecret
import org.cipherboard.cryptocore.PairingCompleted
import org.cipherboard.cryptocore.PairingPayloadMetadata
import org.cipherboard.cryptocore.PairingPayloadStatus
import org.cipherboard.cryptocore.PairingPayloadType
import org.cipherboard.cryptocore.PairingResponseCreated
import org.cipherboard.pairing.PairingQrPayload
import org.cipherboard.pairing.PairingQrPayloadException
import org.cipherboard.pairing.PairingQrPayloadType
import org.cipherboard.securestorage.ContactVaultEntry
import org.cipherboard.securestorage.ContactVaultRepository
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.OneShotStatus
import org.cipherboard.securestorage.OwnerIdentityAccountState
import org.cipherboard.securestorage.OwnedSecret as StorageOwnedSecret
import org.cipherboard.securestorage.PendingPairingState
import org.cipherboard.securestorage.PendingPairingType
import org.cipherboard.securestorage.VersionedDomainRecord
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

internal interface PairingCryptoOperations {
    fun createOffer(
        accountState: CryptoOwnedSecret,
        nowEpochSeconds: Long,
        ttlSeconds: Long,
        capabilities: Long,
    ): OfferCreated

    fun respondToOffer(
        accountState: CryptoOwnedSecret,
        offerQr: ByteArray,
        nowEpochSeconds: Long,
        capabilities: Long,
    ): PairingResponseCreated

    fun completePairing(
        accountState: CryptoOwnedSecret,
        offerQr: ByteArray,
        responseQr: ByteArray,
        nowEpochSeconds: Long,
    ): PairingCompleted

    fun parsePairingPayload(qrPayload: ByteArray, nowEpochSeconds: Long): PairingPayloadMetadata
}

internal class NativePairingCrypto(
    private val delegate: CipherBoardCrypto,
) : PairingCryptoOperations {
    override fun createOffer(
        accountState: CryptoOwnedSecret,
        nowEpochSeconds: Long,
        ttlSeconds: Long,
        capabilities: Long,
    ) = delegate.createOffer(accountState, nowEpochSeconds, ttlSeconds, capabilities)

    override fun respondToOffer(
        accountState: CryptoOwnedSecret,
        offerQr: ByteArray,
        nowEpochSeconds: Long,
        capabilities: Long,
    ) = delegate.respondToOffer(accountState, offerQr, nowEpochSeconds, capabilities)

    override fun completePairing(
        accountState: CryptoOwnedSecret,
        offerQr: ByteArray,
        responseQr: ByteArray,
        nowEpochSeconds: Long,
    ) = delegate.completePairing(accountState, offerQr, responseQr, nowEpochSeconds)

    override fun parsePairingPayload(qrPayload: ByteArray, nowEpochSeconds: Long) =
        delegate.parsePairingPayload(qrPayload, nowEpochSeconds)
}

internal interface PairingVaultOperations {
    fun readOwner(): VersionedDomainRecord<OwnerIdentityAccountState>?
    fun readPending(pairingId: ByteArray): VersionedDomainRecord<PendingPairingState>?
    fun readContact(contactId: ByteArray): VersionedDomainRecord<ContactVaultEntry>?
    fun listContacts(): List<VersionedDomainRecord<ContactVaultEntry>>
    fun listActivePending(limit: Int): List<VersionedDomainRecord<PendingPairingState>>

    fun stage(
        expectedOwnerRevision: Long,
        updatedOwner: OwnerIdentityAccountState,
        pending: PendingPairingState,
    ): Boolean

    fun complete(
        pairingId: ByteArray,
        expectedPairingRevision: Long,
        expectedOwnerRevision: Long,
        expectedContactRevision: Long,
        nowEpochMillis: Long,
        updatedOwner: OwnerIdentityAccountState,
        contact: ContactVaultEntry,
        initialRatchetState: StorageOwnedSecret,
        allowIdentityReplacement: Boolean,
    ): Boolean

    fun cancel(pairingId: ByteArray, expectedRevision: Long): Boolean
    fun expire(pairingId: ByteArray, expectedRevision: Long, nowEpochMillis: Long): Boolean
}

internal class RepositoryPairingVault(
    private val delegate: ContactVaultRepository,
) : PairingVaultOperations {
    override fun readOwner() = delegate.readOwnerAccount()
    override fun readPending(pairingId: ByteArray) = delegate.readPendingPairing(pairingId)
    override fun readContact(contactId: ByteArray) = delegate.readContact(contactId)
    override fun listContacts() = delegate.listContacts()
    override fun listActivePending(limit: Int) = delegate.listPendingPairings(
        status = OneShotStatus.ACTIVE,
        limit = limit,
    )

    override fun stage(
        expectedOwnerRevision: Long,
        updatedOwner: OwnerIdentityAccountState,
        pending: PendingPairingState,
    ) = delegate.stagePendingPairing(expectedOwnerRevision, updatedOwner, pending)

    override fun complete(
        pairingId: ByteArray,
        expectedPairingRevision: Long,
        expectedOwnerRevision: Long,
        expectedContactRevision: Long,
        nowEpochMillis: Long,
        updatedOwner: OwnerIdentityAccountState,
        contact: ContactVaultEntry,
        initialRatchetState: StorageOwnedSecret,
        allowIdentityReplacement: Boolean,
    ) = delegate.completePairing(
        pairingId = pairingId,
        expectedPairingRevision = expectedPairingRevision,
        expectedOwnerRevision = expectedOwnerRevision,
        expectedContactRevision = expectedContactRevision,
        nowEpochMillis = nowEpochMillis,
        updatedOwnerAccount = updatedOwner,
        contact = contact,
        expectedRatchetRevision = 0,
        ratchetSchemaVersion = RATCHET_SCHEMA_VERSION,
        initialRatchetState = initialRatchetState,
        allowIdentityReplacement = allowIdentityReplacement,
    )

    override fun cancel(pairingId: ByteArray, expectedRevision: Long) =
        delegate.cancelPendingPairing(pairingId, expectedRevision)

    override fun expire(pairingId: ByteArray, expectedRevision: Long, nowEpochMillis: Long) =
        delegate.expirePendingPairing(pairingId, expectedRevision, nowEpochMillis)

    private companion object {
        const val RATCHET_SCHEMA_VERSION = 1
    }
}

internal fun interface PairingRandomSource {
    fun nextBytes(destination: ByteArray)
}

internal fun interface EpochMillisSource {
    fun nowEpochMillis(): Long
}

internal object SystemEpochMillisSource : EpochMillisSource {
    override fun nowEpochMillis(): Long = System.currentTimeMillis()
}

internal class SecurePairingRandomSource(
    private val random: SecureRandom = SecureRandom(),
) : PairingRandomSource {
    override fun nextBytes(destination: ByteArray) = random.nextBytes(destination)
}

internal class PairingRuntimeCoordinator(
    private val crypto: PairingCryptoOperations,
    private val vault: PairingVaultOperations,
    private val clock: EpochMillisSource,
    private val random: PairingRandomSource,
) {
    /**
     * Ends abandoned one-shot flows before a new pairing screen starts.
     *
     * Terminal records remain in the vault as replay markers. The repository transition replaces
     * their encrypted payload with a tombstone, so abandoned responder session state is not kept.
     */
    fun cancelActivePairings(): Int {
        val nowMillis = nowMillis()
        var transitioned = 0
        repeat(MAX_PENDING_CLEANUP_BATCHES) {
            val active = vault.listActivePending(PENDING_CLEANUP_BATCH_SIZE)
            if (active.isEmpty()) return transitioned
            var madeProgress = false
            try {
                for (record in active) {
                    val pairingId = record.value.pairingId.copyOf()
                    try {
                        val changed = if (nowMillis > record.value.expiresAtEpochMillis) {
                            vault.expire(pairingId, record.revision, nowMillis)
                        } else {
                            vault.cancel(pairingId, record.revision)
                        }
                        if (changed) {
                            transitioned++
                            madeProgress = true
                        }
                    } finally {
                        pairingId.fill(0)
                    }
                }
            } finally {
                active.forEach { it.close() }
            }
            if (active.size < PENDING_CLEANUP_BATCH_SIZE) return transitioned
            if (!madeProgress) {
                throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
            }
        }
        val remaining = vault.listActivePending(1)
        try {
            if (remaining.isNotEmpty()) {
                throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
            }
        } finally {
            remaining.forEach { it.close() }
        }
        return transitioned
    }

    fun createOffer(
        localContactName: String,
        ttlSeconds: Long,
        capabilities: Long,
        replacementContactId: ByteArray? = null,
    ): PairingOffer {
        require(ttlSeconds in MIN_TTL_SECONDS..MAX_TTL_SECONDS)
        require(capabilities in 0..MAX_CAPABILITIES)
        val nowMillis = nowMillis()
        val nowSeconds = nowMillis / 1_000
        val owner = vault.readOwner() ?: throw PairingRuntimeException(PairingRuntimeError.OWNER_REQUIRED)
        owner.use { versionedOwner ->
            val input = CryptoOwnedSecret.takeOwnership(versionedOwner.value.accountState.copyOf())
            val created = try {
                crypto.createOffer(input, nowSeconds, ttlSeconds, capabilities)
            } catch (error: CryptoCoreException) {
                throw error.asPairingException()
            } finally {
                input.close()
            }
            var metadata: PairingPayloadMetadata? = null
            try {
                val qrPayload = parseQr(created.offerQr, PairingQrPayloadType.OFFER)
                metadata = parseMetadata(created.offerQr, nowSeconds)
                requireMetadataType(metadata, PairingPayloadType.OFFER)
                if (metadata.status == PairingPayloadStatus.EXPIRED) {
                    throw PairingRuntimeException(PairingRuntimeError.EXPIRED)
                }
                if (!metadata.remoteIdentityFingerprint.contentEquals(versionedOwner.value.identityFingerprint)) {
                    throw PairingRuntimeException(PairingRuntimeError.TRANSCRIPT_MISMATCH)
                }
                val expiresMillis = secondsToMillis(
                    metadata.expiresAtEpochSeconds
                        ?: throw PairingRuntimeException(PairingRuntimeError.INVALID_QR),
                )
                val contactId = replacementContactId?.copyOf() ?: uniqueContactId()
                if (replacementContactId != null) requireRepairingContact(contactId).close()
                try {
                    val payload = PendingPairingPayload(
                        role = PendingPairingRole.OFFERER,
                        replacingExistingContact = replacementContactId != null,
                        requestedCapabilities = capabilities,
                        contactId = contactId,
                        localContactName = localContactName,
                        offerQr = created.offerQr,
                        responseQr = EMPTY_BYTES,
                        sessionState = EMPTY_BYTES,
                        remoteFingerprint = EMPTY_BYTES,
                        routingTag = EMPTY_BYTES,
                        safetyNumber = "",
                        safetyCode = "",
                    )
                    payload.use { pendingPayload ->
                        val encoded = PendingPairingPayloadCodec.encode(pendingPayload)
                        try {
                            val pending = PendingPairingState(
                                type = PendingPairingType.OFFER,
                                pairingId = metadata.pairingId,
                                createdAtEpochMillis = nowMillis,
                                expiresAtEpochMillis = expiresMillis,
                                nonce = metadata.nonce,
                                transcriptHash = metadata.offerHash,
                                oneShotStatus = OneShotStatus.ACTIVE,
                                protocolVersion = versionedOwner.value.protocolVersion,
                                payload = encoded,
                            )
                            pending.use {
                                val updatedOwner = created.accountState.use { accountBytes ->
                                    ownerWithAccount(versionedOwner.value, accountBytes)
                                }
                                updatedOwner.use {
                                    if (!vault.stage(versionedOwner.revision, it, pending)) {
                                        throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
                                    }
                                }
                            }
                        } finally {
                            encoded.fill(0)
                        }
                    }
                    return PairingOffer(qrPayload, metadata.pairingId, expiresMillis)
                } finally {
                    contactId.fill(0)
                }
            } finally {
                created.accountState.close()
                created.offerQr.fill(0)
                metadata?.wipe()
            }
        }
    }

    fun respondToOffer(
        localContactName: String,
        offerQr: PairingQrPayload,
        capabilities: Long,
        replacementContactId: ByteArray? = null,
    ): PairingResponse {
        require(capabilities in 0..MAX_CAPABILITIES)
        if (offerQr.type != PairingQrPayloadType.OFFER) {
            throw PairingRuntimeException(PairingRuntimeError.WRONG_QR_TYPE)
        }
        val nowMillis = nowMillis()
        val nowSeconds = nowMillis / 1_000
        val offerBytes = offerQr.value.toByteArray(StandardCharsets.US_ASCII)
        var offerMetadata: PairingPayloadMetadata? = null
        try {
            offerMetadata = parseMetadata(offerBytes, nowSeconds)
            requireMetadataType(offerMetadata, PairingPayloadType.OFFER)
            if (offerMetadata.status == PairingPayloadStatus.EXPIRED) {
                throw PairingRuntimeException(PairingRuntimeError.EXPIRED)
            }
            val expiresMillis = secondsToMillis(
                offerMetadata.expiresAtEpochSeconds
                    ?: throw PairingRuntimeException(PairingRuntimeError.INVALID_QR),
            )
            resumeResponseIfPresent(
                metadata = offerMetadata,
                offerBytes = offerBytes,
                nowMillis = nowMillis,
                requestedLocalName = localContactName,
                requestedCapabilities = capabilities,
                requestedReplacementContactId = replacementContactId,
            )?.let { return it }

            val owner = vault.readOwner() ?: throw PairingRuntimeException(PairingRuntimeError.OWNER_REQUIRED)
            owner.use { versionedOwner ->
                val input = CryptoOwnedSecret.takeOwnership(versionedOwner.value.accountState.copyOf())
                val response = try {
                    crypto.respondToOffer(input, offerBytes, nowSeconds, capabilities)
                } catch (error: CryptoCoreException) {
                    throw error.asPairingException()
                } finally {
                    input.close()
                }
                var responseMetadata: PairingPayloadMetadata? = null
                try {
                    val responseQr = parseQr(response.responseQr, PairingQrPayloadType.RESPONSE)
                    responseMetadata = parseMetadata(response.responseQr, nowSeconds)
                    requireMetadataType(responseMetadata, PairingPayloadType.RESPONSE)
                    requireSameTranscript(offerMetadata, responseMetadata)
                    if (!response.remoteIdentityFingerprint.contentEquals(
                            offerMetadata.remoteIdentityFingerprint,
                        ) || !responseMetadata.remoteIdentityFingerprint.contentEquals(
                            versionedOwner.value.identityFingerprint,
                        )
                    ) {
                        throw PairingRuntimeException(PairingRuntimeError.TRANSCRIPT_MISMATCH)
                    }
                    val contactId = replacementContactId?.copyOf() ?: uniqueContactId()
                    val previousFingerprint = previousFingerprintForReplacement(
                        contactId,
                        replacementContactId != null,
                    )
                    try {
                        val sessionBytes = response.sessionState.use { it.copyOf() }
                        val payload = try {
                            PendingPairingPayload(
                                role = PendingPairingRole.RESPONDER,
                                replacingExistingContact = replacementContactId != null,
                                requestedCapabilities = capabilities,
                                contactId = contactId,
                                localContactName = localContactName,
                                offerQr = offerBytes,
                                responseQr = response.responseQr,
                                sessionState = sessionBytes,
                                remoteFingerprint = response.remoteIdentityFingerprint,
                                routingTag = response.routingTag,
                                safetyNumber = response.safetyCode.decimalGroups,
                                safetyCode = response.safetyCode.wordCode,
                            )
                        } finally {
                            sessionBytes.fill(0)
                        }
                        payload.use { pendingPayload ->
                            val encoded = PendingPairingPayloadCodec.encode(pendingPayload)
                            try {
                                val pending = PendingPairingState(
                                    type = PendingPairingType.RESPONSE,
                                    pairingId = offerMetadata.pairingId,
                                    createdAtEpochMillis = nowMillis,
                                    expiresAtEpochMillis = expiresMillis,
                                    nonce = offerMetadata.nonce,
                                    transcriptHash = response.safetyCode.hash,
                                    oneShotStatus = OneShotStatus.ACTIVE,
                                    protocolVersion = versionedOwner.value.protocolVersion,
                                    payload = encoded,
                                )
                                pending.use {
                                    val unchangedOwner = ownerWithAccount(
                                        versionedOwner.value,
                                        versionedOwner.value.accountState,
                                    )
                                    unchangedOwner.use {
                                        if (!vault.stage(versionedOwner.revision, it, pending)) {
                                            throw PairingRuntimeException(PairingRuntimeError.ALREADY_USED)
                                        }
                                    }
                                }
                            } finally {
                                encoded.fill(0)
                            }
                        }
                        val stored = vault.readPending(offerMetadata.pairingId)
                            ?: throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
                        stored.use {
                            return PairingResponse(
                                qrPayload = responseQr,
                                pairingId = offerMetadata.pairingId,
                                remoteFingerprint = response.remoteIdentityFingerprint,
                                previousRemoteFingerprint = previousFingerprint,
                                safetyNumber = response.safetyCode.decimalGroups,
                                safetyCode = response.safetyCode.wordCode,
                                expiresAtEpochMillis = expiresMillis,
                                expectedPendingRevision = it.revision,
                            )
                        }
                    } finally {
                        previousFingerprint.fill(0)
                        contactId.fill(0)
                    }
                } finally {
                    response.sessionState.close()
                    response.responseQr.fill(0)
                    response.safetyCode.hash.fill(0)
                    response.remoteIdentity.curve25519.fill(0)
                    response.remoteIdentity.ed25519.fill(0)
                    response.routingTag.fill(0)
                    response.remoteIdentityFingerprint.fill(0)
                    responseMetadata?.wipe()
                }
            }
        } finally {
            offerBytes.fill(0)
            offerMetadata?.wipe()
        }
    }

    fun prepareResponse(responseQr: PairingQrPayload): PreparedPairingConfirmation {
        if (responseQr.type != PairingQrPayloadType.RESPONSE) {
            throw PairingRuntimeException(PairingRuntimeError.WRONG_QR_TYPE)
        }
        val nowMillis = nowMillis()
        val nowSeconds = nowMillis / 1_000
        val responseBytes = responseQr.value.toByteArray(StandardCharsets.US_ASCII)
        var responseMetadata: PairingPayloadMetadata? = null
        try {
            responseMetadata = parseMetadata(responseBytes, nowSeconds)
            requireMetadataType(responseMetadata, PairingPayloadType.RESPONSE)
            val pending = requireActivePending(responseMetadata.pairingId, nowMillis)
            pending.use { versionedPending ->
                if (versionedPending.value.type != PendingPairingType.OFFER ||
                    !versionedPending.value.transcriptHash.contentEquals(responseMetadata.offerHash)
                ) {
                    throw PairingRuntimeException(PairingRuntimeError.TRANSCRIPT_MISMATCH)
                }
                val decoded = decodePending(versionedPending.value)
                decoded.use { state ->
                    if (state.role != PendingPairingRole.OFFERER) {
                        throw PairingRuntimeException(PairingRuntimeError.ALREADY_USED)
                    }
                    val offerMetadata = parseMetadata(state.offerQr, nowSeconds)
                    try {
                        requireMetadataType(offerMetadata, PairingPayloadType.OFFER)
                        requireSameTranscript(offerMetadata, responseMetadata)
                    } finally {
                        offerMetadata.wipe()
                    }
                    val owner = vault.readOwner()
                        ?: throw PairingRuntimeException(PairingRuntimeError.OWNER_REQUIRED)
                    owner.use { versionedOwner ->
                        val input = CryptoOwnedSecret.takeOwnership(versionedOwner.value.accountState.copyOf())
                        val completed = try {
                            crypto.completePairing(input, state.offerQr, responseBytes, nowSeconds)
                        } catch (error: CryptoCoreException) {
                            throw error.asPairingException()
                        } finally {
                            input.close()
                        }
                        var transferred = false
                        val previousFingerprint = previousFingerprintForReplacement(
                            state.contactId,
                            state.replacingExistingContact,
                        )
                        try {
                            if (!completed.remoteIdentityFingerprint.contentEquals(
                                    responseMetadata.remoteIdentityFingerprint,
                                )
                            ) {
                                throw PairingRuntimeException(PairingRuntimeError.TRANSCRIPT_MISMATCH)
                            }
                            val prepared = PreparedPairingConfirmation(
                                pairingId = responseMetadata.pairingId,
                                contactId = state.contactId,
                                remoteFingerprint = completed.remoteIdentityFingerprint,
                                previousRemoteFingerprint = previousFingerprint,
                                routingTag = completed.routingTag,
                                safetyNumber = completed.safetyCode.decimalGroups,
                                safetyCode = completed.safetyCode.wordCode,
                                expiresAtEpochMillis = versionedPending.value.expiresAtEpochMillis,
                                expectedPendingRevision = versionedPending.revision,
                                expectedOwnerRevision = versionedOwner.revision,
                                localContactName = state.localContactName,
                                replacingExistingContact = state.replacingExistingContact,
                                protocolVersion = versionedOwner.value.protocolVersion,
                                ownerLocalName = versionedOwner.value.localOwnerName,
                                ownerFingerprint = versionedOwner.value.identityFingerprint,
                                ownerCreatedAtEpochMillis = versionedOwner.value.createdAtEpochMillis,
                                updatedAccountState = completed.accountState,
                                initialSessionState = completed.sessionState,
                            )
                            transferred = true
                            return prepared
                        } finally {
                            previousFingerprint.fill(0)
                            if (!transferred) {
                                completed.accountState.close()
                                completed.sessionState.close()
                            }
                            completed.safetyCode.hash.fill(0)
                            completed.remoteIdentity.curve25519.fill(0)
                            completed.remoteIdentity.ed25519.fill(0)
                            completed.routingTag.fill(0)
                            completed.remoteIdentityFingerprint.fill(0)
                        }
                    }
                }
            }
        } finally {
            responseBytes.fill(0)
            responseMetadata?.wipe()
        }
    }

    fun confirm(prepared: PreparedPairingConfirmation): SecureContactSummary {
        prepared.consumeOnce()
        try {
            val nowMillis = nowMillis()
            if (nowMillis > prepared.expiresAtEpochMillis) {
                val expiredId = prepared.pairingId()
                try {
                    expireIfActive(expiredId, nowMillis)
                } finally {
                    expiredId.fill(0)
                }
                throw PairingRuntimeException(PairingRuntimeError.EXPIRED)
            }
            val pairingId = prepared.pairingId()
            val contactId = prepared.contactId()
            val remoteFingerprint = prepared.remoteFingerprint()
            val routingTag = prepared.routingTag()
            val ownerFingerprint = prepared.ownerFingerprint()
            try {
                val target = completionTarget(
                    contactId,
                    prepared.localContactName,
                    prepared.replacingExistingContact,
                    remoteFingerprint,
                )
                val updatedOwner = prepared.updatedAccountState.use { accountBytes ->
                    OwnerIdentityAccountState(
                        localOwnerName = prepared.ownerLocalName,
                        accountState = accountBytes,
                        identityFingerprint = ownerFingerprint,
                        protocolVersion = prepared.protocolVersion,
                        createdAtEpochMillis = prepared.ownerCreatedAtEpochMillis,
                    )
                }
                val contact = completedContact(
                    contactId,
                    target.localName,
                    remoteFingerprint,
                    routingTag,
                    prepared.protocolVersion,
                    prepared.safetyNumber,
                    prepared.safetyCode,
                    nowMillis,
                    target.verificationStatus,
                )
                updatedOwner.use { owner ->
                    contact.use { entry ->
                        val initialRatchet = prepared.initialSessionState.use { session ->
                            StorageOwnedSecret.takeOwnership(session.copyOf())
                        }
                        try {
                            if (!vault.complete(
                                    pairingId,
                                    prepared.expectedPendingRevision,
                                    prepared.expectedOwnerRevision,
                                    target.expectedContactRevision,
                                    nowMillis,
                                    owner,
                                    entry,
                                    initialRatchet,
                                    target.allowIdentityReplacement,
                                )
                            ) {
                                throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
                            }
                        } finally {
                            initialRatchet.close()
                        }
                        return entry.toRuntimeSummary()
                    }
                }
            } finally {
                pairingId.fill(0)
                contactId.fill(0)
                remoteFingerprint.fill(0)
                routingTag.fill(0)
                ownerFingerprint.fill(0)
            }
        } finally {
            prepared.close()
        }
    }

    fun confirm(response: PairingResponse): SecureContactSummary {
        response.requireOpen()
        try {
            val nowMillis = nowMillis()
            val pairingId = response.pairingId()
            try {
                val pending = requireActivePending(pairingId, nowMillis)
                pending.use { versionedPending ->
                    if (versionedPending.revision != response.expectedPendingRevision ||
                        versionedPending.value.type != PendingPairingType.RESPONSE
                    ) {
                        throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
                    }
                    val decoded = decodePending(versionedPending.value)
                    decoded.use { state ->
                        if (state.role != PendingPairingRole.RESPONDER) {
                            throw PairingRuntimeException(PairingRuntimeError.CORRUPT_PENDING_STATE)
                        }
                        val owner = vault.readOwner()
                            ?: throw PairingRuntimeException(PairingRuntimeError.OWNER_REQUIRED)
                        owner.use { versionedOwner ->
                            val target = completionTarget(
                                state.contactId,
                                state.localContactName,
                                state.replacingExistingContact,
                                state.remoteFingerprint,
                            )
                            val unchangedOwner = ownerWithAccount(
                                versionedOwner.value,
                                versionedOwner.value.accountState,
                            )
                            val contact = completedContact(
                                state.contactId,
                                target.localName,
                                state.remoteFingerprint,
                                state.routingTag,
                                versionedOwner.value.protocolVersion,
                                state.safetyNumber,
                                state.safetyCode,
                                nowMillis,
                                target.verificationStatus,
                            )
                            unchangedOwner.use { ownerState ->
                                contact.use { entry ->
                                    val initialRatchet = StorageOwnedSecret.takeOwnership(
                                        state.sessionState.copyOf(),
                                    )
                                    try {
                                        if (!vault.complete(
                                                pairingId,
                                                versionedPending.revision,
                                                versionedOwner.revision,
                                                target.expectedContactRevision,
                                                nowMillis,
                                                ownerState,
                                                entry,
                                                initialRatchet,
                                                target.allowIdentityReplacement,
                                            )
                                        ) {
                                            throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
                                        }
                                    } finally {
                                        initialRatchet.close()
                                    }
                                    return entry.toRuntimeSummary()
                                }
                            }
                        }
                    }
                }
            } finally {
                pairingId.fill(0)
            }
        } finally {
            response.close()
        }
    }

    fun cancel(pairingId: ByteArray): Boolean {
        require(pairingId.size == PendingPairingPayload.CONTACT_ID_BYTES)
        val pending = vault.readPending(pairingId) ?: return false
        pending.use {
            if (it.value.oneShotStatus != OneShotStatus.ACTIVE) return false
            val now = nowMillis()
            return if (now > it.value.expiresAtEpochMillis) {
                vault.expire(pairingId, it.revision, now)
            } else {
                vault.cancel(pairingId, it.revision)
            }
        }
    }

    private fun resumeResponseIfPresent(
        metadata: PairingPayloadMetadata,
        offerBytes: ByteArray,
        nowMillis: Long,
        requestedLocalName: String,
        requestedCapabilities: Long,
        requestedReplacementContactId: ByteArray?,
    ): PairingResponse? {
        val stored = vault.readPending(metadata.pairingId) ?: return null
        stored.use {
            if (it.value.oneShotStatus != OneShotStatus.ACTIVE) {
                throw PairingRuntimeException(PairingRuntimeError.ALREADY_USED)
            }
            if (nowMillis > it.value.expiresAtEpochMillis) {
                vault.expire(metadata.pairingId, it.revision, nowMillis)
                throw PairingRuntimeException(PairingRuntimeError.EXPIRED)
            }
            val state = decodePending(it.value)
            state.use { payload ->
                if (payload.role != PendingPairingRole.RESPONDER ||
                    !payload.offerQr.contentEquals(offerBytes) ||
                    it.value.type != PendingPairingType.RESPONSE ||
                    payload.localContactName != requestedLocalName ||
                    payload.requestedCapabilities != requestedCapabilities ||
                    payload.replacingExistingContact != (requestedReplacementContactId != null) ||
                    (requestedReplacementContactId != null &&
                        !payload.contactId.contentEquals(requestedReplacementContactId))
                ) {
                    throw PairingRuntimeException(PairingRuntimeError.ALREADY_USED)
                }
                val responseMetadata = parseMetadata(payload.responseQr, nowMillis / 1_000)
                try {
                    requireMetadataType(responseMetadata, PairingPayloadType.RESPONSE)
                    requireSameTranscript(metadata, responseMetadata)
                } finally {
                    responseMetadata.wipe()
                }
                val responseQr = parseQr(payload.responseQr, PairingQrPayloadType.RESPONSE)
                val previousFingerprint = previousFingerprintForReplacement(
                    payload.contactId,
                    payload.replacingExistingContact,
                )
                try {
                    return PairingResponse(
                        responseQr,
                        metadata.pairingId,
                        payload.remoteFingerprint,
                        previousFingerprint,
                        payload.safetyNumber,
                        payload.safetyCode,
                        it.value.expiresAtEpochMillis,
                        it.revision,
                    )
                } finally {
                    previousFingerprint.fill(0)
                }
            }
        }
    }

    private fun requireActivePending(
        pairingId: ByteArray,
        nowMillis: Long,
    ): VersionedDomainRecord<PendingPairingState> {
        val pending = vault.readPending(pairingId)
            ?: throw PairingRuntimeException(PairingRuntimeError.NOT_FOUND)
        if (pending.value.oneShotStatus != OneShotStatus.ACTIVE) {
            pending.close()
            throw PairingRuntimeException(PairingRuntimeError.ALREADY_USED)
        }
        if (nowMillis > pending.value.expiresAtEpochMillis) {
            val revision = pending.revision
            pending.close()
            vault.expire(pairingId, revision, nowMillis)
            throw PairingRuntimeException(PairingRuntimeError.EXPIRED)
        }
        return pending
    }

    private fun expireIfActive(pairingId: ByteArray, nowMillis: Long) {
        vault.readPending(pairingId)?.use {
            if (it.value.oneShotStatus == OneShotStatus.ACTIVE && nowMillis > it.value.expiresAtEpochMillis) {
                vault.expire(pairingId, it.revision, nowMillis)
            }
        }
    }

    private fun decodePending(value: PendingPairingState): PendingPairingPayload = try {
        PendingPairingPayloadCodec.decode(value.payload)
    } catch (error: IllegalArgumentException) {
        throw PairingRuntimeException(PairingRuntimeError.CORRUPT_PENDING_STATE, error)
    }

    private fun uniqueContactId(): ByteArray {
        repeat(MAX_CONTACT_ID_ATTEMPTS) {
            val candidate = ByteArray(PendingPairingPayload.CONTACT_ID_BYTES)
            random.nextBytes(candidate)
            val existing = vault.readContact(candidate)
            if (existing == null) return candidate
            existing.close()
            candidate.fill(0)
        }
        throw PairingRuntimeException(PairingRuntimeError.CONTACT_ID_COLLISION)
    }

    private fun requireRepairingContact(
        contactId: ByteArray,
    ): VersionedDomainRecord<ContactVaultEntry> {
        val contact = vault.readContact(contactId)
            ?: throw PairingRuntimeException(PairingRuntimeError.NOT_FOUND)
        if (!contact.value.requiresRepairing) {
            contact.close()
            throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
        }
        return contact
    }

    private fun completionTarget(
        contactId: ByteArray,
        pendingLocalName: String,
        replacingExisting: Boolean,
        remoteFingerprint: ByteArray,
    ): PairingCompletionTarget {
        ensureRemoteIdentityUnique(contactId, remoteFingerprint)
        val current = vault.readContact(contactId)
        if (!replacingExisting) {
            current?.close()
            if (current != null) {
                throw PairingRuntimeException(PairingRuntimeError.CONTACT_ID_COLLISION)
            }
            return PairingCompletionTarget(
                pendingLocalName,
                0,
                false,
                ContactVerificationStatus.VERIFIED,
            )
        }
        if (current == null) throw PairingRuntimeException(PairingRuntimeError.NOT_FOUND)
        current.use {
            if (!it.value.requiresRepairing) {
                throw PairingRuntimeException(PairingRuntimeError.STATE_CONFLICT)
            }
            val verificationStatus = if (it.value.remoteIdentityFingerprint.contentEquals(remoteFingerprint)) {
                ContactVerificationStatus.VERIFIED
            } else {
                ContactVerificationStatus.KEY_CHANGED
            }
            return PairingCompletionTarget(it.value.localName, it.revision, true, verificationStatus)
        }
    }

    private fun ensureRemoteIdentityUnique(contactId: ByteArray, remoteFingerprint: ByteArray) {
        val existing = vault.listContacts()
        try {
            if (existing.any {
                    !it.value.internalId.contentEquals(contactId) &&
                        it.value.remoteIdentityFingerprint.contentEquals(remoteFingerprint)
                }
            ) {
                throw PairingRuntimeException(PairingRuntimeError.CONTACT_ALREADY_EXISTS)
            }
        } finally {
            existing.forEach { it.close() }
        }
    }

    private fun previousFingerprintForReplacement(
        contactId: ByteArray,
        replacingExisting: Boolean,
    ): ByteArray {
        if (!replacingExisting) return ByteArray(0)
        return requireRepairingContact(contactId).use {
            it.value.remoteIdentityFingerprint.copyOf()
        }
    }

    private fun parseMetadata(bytes: ByteArray, nowSeconds: Long): PairingPayloadMetadata = try {
        crypto.parsePairingPayload(bytes, nowSeconds)
    } catch (error: CryptoCoreException) {
        throw error.asPairingException()
    } catch (error: IllegalArgumentException) {
        throw PairingRuntimeException(PairingRuntimeError.INVALID_QR, error)
    }

    private fun parseQr(bytes: ByteArray, expectedType: PairingQrPayloadType): PairingQrPayload {
        if (bytes.isEmpty() || bytes.size > PendingPairingPayload.MAX_QR_BYTES ||
            bytes.any { it.toInt() and 0xff !in 0x21..0x7e }
        ) {
            throw PairingRuntimeException(PairingRuntimeError.INVALID_QR)
        }
        val parsed = try {
            PairingQrPayload.parse(String(bytes, StandardCharsets.US_ASCII))
        } catch (error: PairingQrPayloadException) {
            throw PairingRuntimeException(PairingRuntimeError.INVALID_QR, error)
        }
        if (parsed.type != expectedType) {
            throw PairingRuntimeException(PairingRuntimeError.WRONG_QR_TYPE)
        }
        return parsed
    }

    private fun requireMetadataType(metadata: PairingPayloadMetadata, type: PairingPayloadType) {
        if (metadata.type != type) throw PairingRuntimeException(PairingRuntimeError.WRONG_QR_TYPE)
    }

    private fun requireSameTranscript(offer: PairingPayloadMetadata, response: PairingPayloadMetadata) {
        if (!offer.pairingId.contentEquals(response.pairingId) ||
            !offer.offerHash.contentEquals(response.offerHash)
        ) {
            throw PairingRuntimeException(PairingRuntimeError.TRANSCRIPT_MISMATCH)
        }
    }

    private fun ownerWithAccount(
        owner: OwnerIdentityAccountState,
        accountBytes: ByteArray,
    ) = OwnerIdentityAccountState(
        localOwnerName = owner.localOwnerName,
        accountState = accountBytes,
        identityFingerprint = owner.identityFingerprint,
        protocolVersion = owner.protocolVersion,
        createdAtEpochMillis = owner.createdAtEpochMillis,
    )

    private fun completedContact(
        contactId: ByteArray,
        localName: String,
        remoteFingerprint: ByteArray,
        routingTag: ByteArray,
        protocolVersion: Int,
        safetyNumber: String,
        safetyCode: String,
        nowMillis: Long,
        verificationStatus: ContactVerificationStatus,
    ) = ContactVaultEntry(
        internalId = contactId,
        localName = localName,
        remoteIdentityFingerprint = remoteFingerprint,
        remoteSessionTag = routingTag,
        verificationStatus = verificationStatus,
        pairedAtEpochMillis = nowMillis,
        lastActiveAtEpochMillis = nowMillis,
        protocolVersion = protocolVersion,
        safetyNumber = safetyNumber,
        safetyCode = safetyCode,
        requiresRepairing = false,
        sessionError = false,
        keyChanged = verificationStatus == ContactVerificationStatus.KEY_CHANGED,
    )

    private fun ContactVaultEntry.toRuntimeSummary() = SecureContactSummary(
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

    private fun PairingPayloadMetadata.wipe() {
        pairingId.fill(0)
        remoteIdentity.curve25519.fill(0)
        remoteIdentity.ed25519.fill(0)
        remoteIdentityFingerprint.fill(0)
        nonce.fill(0)
        offerHash.fill(0)
    }

    private fun CryptoCoreException.asPairingException(): PairingRuntimeException =
        PairingRuntimeException(
            when (reason) {
                CryptoErrorCode.EXPIRED_OFFER -> PairingRuntimeError.EXPIRED
                CryptoErrorCode.PAIRING_ALREADY_USED -> PairingRuntimeError.ALREADY_USED
                CryptoErrorCode.INVALID_TRANSCRIPT,
                CryptoErrorCode.INVALID_SIGNATURE,
                -> PairingRuntimeError.TRANSCRIPT_MISMATCH
                else -> PairingRuntimeError.INVALID_QR
            },
            this,
        )

    private fun nowMillis(): Long = clock.nowEpochMillis().also { require(it >= 0) }

    private fun secondsToMillis(value: Long): Long = try {
        Math.multiplyExact(value, 1_000L)
    } catch (error: ArithmeticException) {
        throw PairingRuntimeException(PairingRuntimeError.INVALID_QR, error)
    }

    private companion object {
        const val MIN_TTL_SECONDS = 30L
        const val MAX_TTL_SECONDS = 15L * 60
        const val MAX_CAPABILITIES = 0xffff_ffffL
        const val MAX_CONTACT_ID_ATTEMPTS = 8
        const val PENDING_CLEANUP_BATCH_SIZE = 64
        const val MAX_PENDING_CLEANUP_BATCHES = 16
        val EMPTY_BYTES = ByteArray(0)
    }

    private data class PairingCompletionTarget(
        val localName: String,
        val expectedContactRevision: Long,
        val allowIdentityReplacement: Boolean,
        val verificationStatus: ContactVerificationStatus,
    )
}
