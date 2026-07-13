package org.cipherboard.securestorage

/**
 * Encrypted domain repository for the owner account, contacts and one-shot pairing state.
 *
 * Callers retain ownership of values passed to this class and must close returned records. Every
 * multi-record state transition uses optimistic revisions and one SQLite transaction.
 */
class ContactVaultRepository(
    private val records: VaultRecordStore,
) {
    fun createOwnerAccount(state: OwnerIdentityAccountState): Boolean {
        val encoded = OwnerAccountCodec.encode(state)
        return try {
            records.applyDomainMutations(
                listOf(ownerMutation(expectedRevision = 0, state = encoded)),
            )
        } finally {
            encoded.wipe()
        }
    }

    fun readOwnerAccount(): VersionedDomainRecord<OwnerIdentityAccountState>? =
        records.readDomainRecord(RecordKind.OWNER_ACCOUNT, OWNER_ACCOUNT_KEY)?.use { stored ->
            validateSchema(stored, OWNER_SCHEMA_VERSION)
            val value = stored.secret.consume(OwnerAccountCodec::decode)
            VersionedDomainRecord(stored.revision, value)
        }

    fun updateOwnerAccount(
        expectedRevision: Long,
        state: OwnerIdentityAccountState,
    ): Boolean {
        require(expectedRevision > 0)
        val encoded = OwnerAccountCodec.encode(state)
        return try {
            records.applyDomainMutations(listOf(ownerMutation(expectedRevision, encoded)))
        } finally {
            encoded.wipe()
        }
    }

    /** Atomically advances the owner account and records an unused QR offer or response. */
    fun stagePendingPairing(
        expectedOwnerRevision: Long,
        updatedOwnerAccount: OwnerIdentityAccountState,
        pending: PendingPairingState,
    ): Boolean {
        require(expectedOwnerRevision > 0)
        require(pending.oneShotStatus == OneShotStatus.ACTIVE)
        if (!ensurePendingPairingCapacity(pending.createdAtEpochMillis)) return false
        val owner = OwnerAccountCodec.encode(updatedOwnerAccount)
        return try {
            val pairing = PendingPairingCodec.encode(pending)
            try {
                records.applyDomainMutations(
                    listOf(
                        ownerMutation(expectedOwnerRevision, owner),
                        DomainMutation.Put(
                            RecordKind.PENDING_PAIRING,
                            pairingKey(pending.pairingId),
                            OWNER_ACCOUNT_KEY,
                            PAIRING_SCHEMA_VERSION,
                            expectedRevision = 0,
                            plaintext = pairing,
                        ),
                    )
                )
            } finally {
                pairing.wipe()
            }
        } finally {
            owner.wipe()
        }
    }

    fun readPendingPairing(pairingId: ByteArray): VersionedDomainRecord<PendingPairingState>? =
        records.readDomainRecord(RecordKind.PENDING_PAIRING, pairingKey(pairingId))?.use { stored ->
            validateSchema(stored, PAIRING_SCHEMA_VERSION)
            val value = stored.secret.consume(PendingPairingCodec::decode)
            if (!value.pairingId.contentEquals(pairingId)) {
                value.close()
                throw VaultCorruptException("Pending pairing identifier does not match its index")
            }
            VersionedDomainRecord(stored.revision, value)
        }

    fun listPendingPairings(
        status: OneShotStatus? = null,
        expiresNotBeforeEpochMillis: Long? = null,
        expiresNotAfterEpochMillis: Long? = null,
        limit: Int = MAX_PENDING_RESULTS,
        newestFirst: Boolean = true,
    ): List<VersionedDomainRecord<PendingPairingState>> {
        require(limit in 1..MAX_PENDING_SCAN_RESULTS)
        require(expiresNotBeforeEpochMillis == null || expiresNotBeforeEpochMillis >= 0)
        require(expiresNotAfterEpochMillis == null || expiresNotAfterEpochMillis >= 0)
        require(
            expiresNotBeforeEpochMillis == null || expiresNotAfterEpochMillis == null ||
                expiresNotBeforeEpochMillis <= expiresNotAfterEpochMillis,
        )
        val stored = records.listDomainRecords(
            RecordKind.PENDING_PAIRING,
            MAX_PENDING_SCAN_RESULTS,
            newestFirst,
        )
        val decoded = ArrayList<VersionedDomainRecord<PendingPairingState>>(limit)
        try {
            for (record in stored) {
                if (decoded.size == limit) break
                record.use {
                    validateSchema(it, PAIRING_SCHEMA_VERSION)
                    val value = it.secret.consume(PendingPairingCodec::decode)
                    if (it.recordKey != pairingKey(value.pairingId)) {
                        value.close()
                        throw VaultCorruptException("Pending pairing identifier does not match its index")
                    }
                    val matches = (status == null || value.oneShotStatus == status) &&
                        (expiresNotBeforeEpochMillis == null ||
                            value.expiresAtEpochMillis >= expiresNotBeforeEpochMillis) &&
                        (expiresNotAfterEpochMillis == null ||
                            value.expiresAtEpochMillis <= expiresNotAfterEpochMillis)
                    if (matches) {
                        decoded += VersionedDomainRecord(it.revision, value)
                    } else {
                        value.close()
                    }
                }
            }
            return decoded
        } catch (error: Exception) {
            decoded.forEach { it.close() }
            throw error
        } finally {
            stored.forEach { it.close() }
        }
    }

    fun listActivePendingPairings(
        nowEpochMillis: Long,
        limit: Int = MAX_PENDING_RESULTS,
    ): List<VersionedDomainRecord<PendingPairingState>> {
        require(nowEpochMillis >= 0)
        return listPendingPairings(
            status = OneShotStatus.ACTIVE,
            expiresNotBeforeEpochMillis = nowEpochMillis,
            limit = limit,
        )
    }

    /**
     * Consumes one pending pairing and commits the resulting account and contact/session together.
     * A stale revision, expired offer or already-consumed offer leaves all four records unchanged.
     * The ratchet is never copied into [ContactVaultEntry].
     */
    @Synchronized
    fun completePairing(
        pairingId: ByteArray,
        expectedPairingRevision: Long,
        expectedOwnerRevision: Long,
        expectedContactRevision: Long,
        nowEpochMillis: Long,
        updatedOwnerAccount: OwnerIdentityAccountState,
        contact: ContactVaultEntry,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        initialRatchetState: OwnedSecret,
        allowIdentityReplacement: Boolean = false,
    ): Boolean {
        require(expectedPairingRevision > 0 && expectedOwnerRevision > 0)
        require(expectedContactRevision >= 0 && expectedRatchetRevision >= 0 && nowEpochMillis >= 0)
        require(ratchetSchemaVersion > 0)
        require(expectedContactRevision > 0 || expectedRatchetRevision == 0L)
        if (hasConflictingRemoteIdentity(contact)) return false
        if (expectedContactRevision > 0) {
            val existing = readContact(contact.internalId) ?: return false
            existing.use {
                if (it.revision != expectedContactRevision) return false
                if (!it.value.requiresRepairing) return false
                val identityChanged = !it.value.remoteIdentityFingerprint.contentEquals(
                    contact.remoteIdentityFingerprint,
                )
                if (identityChanged &&
                    (!allowIdentityReplacement ||
                        contact.verificationStatus != ContactVerificationStatus.KEY_CHANGED ||
                        !contact.keyChanged || contact.requiresRepairing || contact.sessionError)
                ) {
                    return false
                }
            }
        }
        val pendingRecord = readPendingPairing(pairingId) ?: return false
        pendingRecord.use { versioned ->
            if (versioned.revision != expectedPairingRevision ||
                versioned.value.oneShotStatus != OneShotStatus.ACTIVE ||
                nowEpochMillis > versioned.value.expiresAtEpochMillis
            ) {
                return false
            }
            val consumed = versioned.value.copyWithStatus(OneShotStatus.CONSUMED)
            consumed.use {
                val ratchet = initialRatchetState.take()
                return try {
                    commitCompletedPairing(
                        expectedOwnerRevision,
                        expectedContactRevision,
                        updatedOwnerAccount,
                        contact,
                        expectedPairingRevision,
                        consumed,
                        expectedRatchetRevision,
                        ratchetSchemaVersion,
                        ratchet,
                    )
                } finally {
                    ratchet.wipe()
                }
            }
        }
    }

    fun cancelPendingPairing(pairingId: ByteArray, expectedRevision: Long): Boolean =
        transitionPendingPairing(pairingId, expectedRevision, OneShotStatus.CANCELLED)

    fun expirePendingPairing(pairingId: ByteArray, expectedRevision: Long, nowEpochMillis: Long): Boolean {
        require(nowEpochMillis >= 0)
        val pending = readPendingPairing(pairingId) ?: return false
        pending.use {
            if (it.revision != expectedRevision || nowEpochMillis <= it.value.expiresAtEpochMillis) return false
        }
        return transitionPendingPairing(pairingId, expectedRevision, OneShotStatus.EXPIRED)
    }

    fun deletePendingPairing(pairingId: ByteArray, expectedRevision: Long): Boolean {
        require(expectedRevision > 0)
        return records.applyDomainMutations(
            listOf(DomainMutation.Delete(RecordKind.PENDING_PAIRING, pairingKey(pairingId), expectedRevision)),
        )
    }

    fun readContact(contactId: ByteArray): VersionedDomainRecord<ContactVaultEntry>? =
        records.readDomainRecord(RecordKind.CONTACT, contactKey(contactId))?.use { stored ->
            validateSchema(stored, CONTACT_SCHEMA_VERSION)
            val value = stored.secret.consume(ContactEntryCodec::decode)
            if (!value.internalId.contentEquals(contactId)) {
                value.close()
                throw VaultCorruptException("Contact identifier does not match its index")
            }
            VersionedDomainRecord(stored.revision, value)
        }

    fun listContacts(limit: Int = MAX_CONTACT_RESULTS): List<VersionedDomainRecord<ContactVaultEntry>> {
        require(limit in 1..MAX_CONTACT_RESULTS)
        val stored = records.listDomainRecords(RecordKind.CONTACT, limit)
        val decoded = ArrayList<VersionedDomainRecord<ContactVaultEntry>>(stored.size)
        try {
            stored.forEach { record ->
                record.use {
                    validateSchema(it, CONTACT_SCHEMA_VERSION)
                    val value = it.secret.consume(ContactEntryCodec::decode)
                    if (it.recordKey != contactKey(value.internalId)) {
                        value.close()
                        throw VaultCorruptException("Contact identifier does not match its index")
                    }
                    decoded += VersionedDomainRecord(it.revision, value)
                }
            }
            return decoded
        } catch (error: Exception) {
            decoded.forEach(VersionedDomainRecord<ContactVaultEntry>::close)
            throw error
        } finally {
            stored.forEach(DomainStoredSecret::close)
        }
    }

    fun renameContact(contactId: ByteArray, expectedRevision: Long, localName: String): Boolean =
        updateContact(contactId, expectedRevision) { it.copyWith(localName = localName) }

    fun updateContactStatus(
        contactId: ByteArray,
        expectedRevision: Long,
        verificationStatus: ContactVerificationStatus,
        requiresRepairing: Boolean,
        sessionError: Boolean,
        keyChanged: Boolean,
        lastActiveAtEpochMillis: Long,
    ): Boolean = updateContact(contactId, expectedRevision) {
        it.copyWith(
            verificationStatus = verificationStatus,
            requiresRepairing = requiresRepairing,
            sessionError = sessionError,
            keyChanged = keyChanged,
            lastActiveAtEpochMillis = lastActiveAtEpochMillis,
        )
    }

    fun commitOutbound(
        contactId: ByteArray,
        expectedContactRevision: Long,
        lastActiveAtEpochMillis: Long,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        operationId: ByteArray,
        pendingCiphertext: ByteArray,
    ) {
        try {
            require(expectedContactRevision > 0 && lastActiveAtEpochMillis >= 0)
            val current = readContact(contactId) ?: throw RatchetRevisionConflictException()
            current.use {
                if (it.revision != expectedContactRevision) throw RatchetRevisionConflictException()
                val changed = it.value.copyWith(
                    lastActiveAtEpochMillis = maxOf(lastActiveAtEpochMillis, it.value.lastActiveAtEpochMillis),
                )
                changed.use { value ->
                    val encoded = ContactEntryCodec.encode(value)
                    try {
                        records.commitOutboundWithDomainMutation(
                            contactId,
                            expectedRatchetRevision,
                            ratchetSchemaVersion,
                            newRatchetState,
                            operationId,
                            pendingCiphertext,
                            contactMutation(contactId, expectedContactRevision, encoded),
                        )
                    } finally {
                        encoded.wipe()
                    }
                }
            }
        } finally {
            newRatchetState.close()
        }
    }

    fun commitInbound(
        contactId: ByteArray,
        expectedContactRevision: Long,
        lastActiveAtEpochMillis: Long,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        messageId: ByteArray,
        ciphertextDigest: ByteArray,
        pendingPlaintext: OwnedSecret,
    ): AtomicInboundResult {
        try {
            require(expectedContactRevision > 0 && lastActiveAtEpochMillis >= 0)
            val current = readContact(contactId) ?: return AtomicInboundResult.REVISION_CONFLICT
            current.use {
                if (it.revision != expectedContactRevision) return AtomicInboundResult.REVISION_CONFLICT
                val changed = it.value.copyWith(
                    lastActiveAtEpochMillis = maxOf(lastActiveAtEpochMillis, it.value.lastActiveAtEpochMillis),
                )
                changed.use { value ->
                    val encoded = ContactEntryCodec.encode(value)
                    return try {
                        records.commitInboundWithDomainMutation(
                            contactId,
                            expectedRatchetRevision,
                            ratchetSchemaVersion,
                            newRatchetState,
                            messageId,
                            ciphertextDigest,
                            pendingPlaintext,
                            contactMutation(contactId, expectedContactRevision, encoded),
                        )
                    } finally {
                        encoded.wipe()
                    }
                }
            }
        } finally {
            newRatchetState.close()
            pendingPlaintext.close()
        }
    }

    fun destroyContactSession(
        contactId: ByteArray,
        expectedRevision: Long,
        expectedRatchetRevision: Long,
        lastActiveAtEpochMillis: Long,
    ): Boolean {
        require(expectedRevision > 0 && expectedRatchetRevision > 0)
        val current = readContact(contactId) ?: return false
        current.use {
            if (it.revision != expectedRevision) return false
            val changed = it.value.copyWith(
                verificationStatus = ContactVerificationStatus.PAIRING_REQUIRED,
                requiresRepairing = true,
                sessionError = false,
                keyChanged = false,
                lastActiveAtEpochMillis = lastActiveAtEpochMillis,
            )
            changed.use { value ->
                val encoded = ContactEntryCodec.encode(value)
                return try {
                    records.applyDomainMutations(
                        listOf(contactMutation(contactId, expectedRevision, encoded)),
                        RatchetMutation.Delete(contactId, expectedRatchetRevision),
                    )
                } finally {
                    encoded.wipe()
                }
            }
        }
    }

    /** Deletes contact metadata, session state, pending message records and replay markers. */
    fun deleteContact(contactId: ByteArray, expectedRevision: Long): Boolean {
        require(expectedRevision > 0)
        return records.applyDomainMutations(
            listOf(
                DomainMutation.Delete(
                    RecordKind.CONTACT,
                    contactKey(contactId),
                    expectedRevision,
                    cascadeOwnerKey = IdentifierCodec.contactKey(contactId),
                ),
            ),
        )
    }

    private fun commitCompletedPairing(
        expectedOwnerRevision: Long,
        expectedContactRevision: Long,
        updatedOwnerAccount: OwnerIdentityAccountState,
        contact: ContactVaultEntry,
        expectedPairingRevision: Long,
        consumedPairing: PendingPairingState,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        initialRatchetState: ByteArray,
    ): Boolean {
        val owner = OwnerAccountCodec.encode(updatedOwnerAccount)
        return try {
            val pairing = PendingPairingCodec.encode(consumedPairing)
            try {
                val encodedContact = ContactEntryCodec.encode(contact)
                try {
                    records.applyDomainMutations(
                        listOf(
                            ownerMutation(expectedOwnerRevision, owner),
                            DomainMutation.Put(
                                RecordKind.PENDING_PAIRING,
                                pairingKey(consumedPairing.pairingId),
                                OWNER_ACCOUNT_KEY,
                                PAIRING_SCHEMA_VERSION,
                                expectedPairingRevision,
                                pairing,
                            ),
                            contactMutation(contact.internalId, expectedContactRevision, encodedContact),
                        ),
                        RatchetMutation.Put(
                            contactId = contact.internalId,
                            expectedRevision = expectedRatchetRevision,
                            schemaVersion = ratchetSchemaVersion,
                            plaintext = initialRatchetState,
                            purgePreviousSessionArtifacts = expectedContactRevision > 0,
                        ),
                    )
                } finally {
                    encodedContact.wipe()
                }
            } finally {
                pairing.wipe()
            }
        } finally {
            owner.wipe()
        }
    }

    private fun ensurePendingPairingCapacity(nowEpochMillis: Long): Boolean {
        val cutoff = (nowEpochMillis - PAIRING_TOMBSTONE_RETENTION_MILLIS).coerceAtLeast(0)
        val oldest = listPendingPairings(
            limit = MAX_PENDING_SCAN_RESULTS,
            newestFirst = false,
        )
        try {
            oldest.forEach { record ->
                if (record.value.oneShotStatus != OneShotStatus.ACTIVE &&
                    record.value.createdAtEpochMillis <= cutoff
                ) {
                    deletePendingPairing(record.value.pairingId, record.revision)
                }
            }
        } finally {
            oldest.forEach(VersionedDomainRecord<PendingPairingState>::close)
        }
        return records.countDomainRecords(RecordKind.PENDING_PAIRING) < MAX_STORED_PAIRING_RECORDS
    }

    private fun transitionPendingPairing(
        pairingId: ByteArray,
        expectedRevision: Long,
        newStatus: OneShotStatus,
    ): Boolean {
        require(expectedRevision > 0)
        require(newStatus == OneShotStatus.CANCELLED || newStatus == OneShotStatus.EXPIRED)
        val pending = readPendingPairing(pairingId) ?: return false
        pending.use {
            if (it.revision != expectedRevision || it.value.oneShotStatus != OneShotStatus.ACTIVE) return false
            val changed = it.value.copyWithStatus(newStatus)
            changed.use { value ->
                val encoded = PendingPairingCodec.encode(value)
                return try {
                    records.applyDomainMutations(
                        listOf(
                            DomainMutation.Put(
                                RecordKind.PENDING_PAIRING,
                                pairingKey(pairingId),
                                OWNER_ACCOUNT_KEY,
                                PAIRING_SCHEMA_VERSION,
                                expectedRevision,
                                encoded,
                            ),
                        ),
                    )
                } finally {
                    encoded.wipe()
                }
            }
        }
    }

    private inline fun updateContact(
        contactId: ByteArray,
        expectedRevision: Long,
        transform: (ContactVaultEntry) -> ContactVaultEntry,
    ): Boolean {
        require(expectedRevision > 0)
        val current = readContact(contactId) ?: return false
        current.use {
            if (it.revision != expectedRevision) return false
            val changed = transform(it.value)
            changed.use { value ->
                val encoded = ContactEntryCodec.encode(value)
                return try {
                    records.applyDomainMutations(
                        listOf(contactMutation(contactId, expectedRevision, encoded)),
                    )
                } finally {
                    encoded.wipe()
                }
            }
        }
    }

    private fun ownerMutation(expectedRevision: Long, state: ByteArray) = DomainMutation.Put(
        RecordKind.OWNER_ACCOUNT,
        OWNER_ACCOUNT_KEY,
        OWNER_ACCOUNT_KEY,
        OWNER_SCHEMA_VERSION,
        expectedRevision,
        state,
    )

    private fun contactMutation(contactId: ByteArray, expectedRevision: Long, value: ByteArray) =
        DomainMutation.Put(
            RecordKind.CONTACT,
            contactKey(contactId),
            IdentifierCodec.contactKey(contactId),
            CONTACT_SCHEMA_VERSION,
            expectedRevision,
            value,
        )

    private fun validateSchema(stored: DomainStoredSecret, expectedVersion: Int) {
        if (stored.schemaVersion != expectedVersion) {
            throw DomainCodecException(DomainCodecError.UNSUPPORTED_VERSION)
        }
    }

    private fun contactKey(contactId: ByteArray) = IdentifierCodec.domainKey("vault-contact", contactId)
    private fun pairingKey(pairingId: ByteArray) = IdentifierCodec.domainKey("pending-pairing", pairingId)

    private fun hasConflictingRemoteIdentity(candidate: ContactVaultEntry): Boolean {
        val existing = listContacts()
        return try {
            existing.any { record ->
                !record.value.internalId.contentEquals(candidate.internalId) &&
                    (record.value.remoteIdentityFingerprint.contentEquals(candidate.remoteIdentityFingerprint) ||
                        record.value.remoteSessionTag.contentEquals(candidate.remoteSessionTag))
            }
        } finally {
            existing.forEach(VersionedDomainRecord<ContactVaultEntry>::close)
        }
    }

    private object RecordKind {
        const val OWNER_ACCOUNT = 10
        const val CONTACT = 11
        const val PENDING_PAIRING = 12
    }

    companion object {
        private const val OWNER_SCHEMA_VERSION = 1
        private const val PAIRING_SCHEMA_VERSION = 1
        private const val CONTACT_SCHEMA_VERSION = 2
        private const val MAX_CONTACT_RESULTS = 1_024
        private const val MAX_PENDING_RESULTS = 256
        private const val MAX_PENDING_SCAN_RESULTS = 1_024
        private const val MAX_STORED_PAIRING_RECORDS = 512
        private const val PAIRING_TOMBSTONE_RETENTION_MILLIS = 7L * 24 * 60 * 60 * 1_000
        private val OWNER_ACCOUNT_KEY = IdentifierCodec.singletonKey("owner-account")
    }
}
