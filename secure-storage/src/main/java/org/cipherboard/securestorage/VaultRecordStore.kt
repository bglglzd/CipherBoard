package org.cipherboard.securestorage

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import java.io.Closeable

enum class AtomicInboundResult {
    COMMITTED,
    REPLAY,
    REVISION_CONFLICT,
}

data class VersionedSecret(
    val schemaVersion: Int,
    val revision: Long,
    val secret: OwnedSecret,
) : Closeable {
    override fun close() = secret.close()
}

data class PendingOutbound(
    val contactId: ByteArray,
    val operationId: ByteArray,
    val ciphertext: ByteArray,
    val revision: Long,
)

data class PendingDisplay(
    val messageId: ByteArray,
    val ciphertextDigest: ByteArray,
    val plaintext: OwnedSecret,
    val revision: Long,
) : Closeable {
    override fun close() {
        messageId.wipe()
        ciphertextDigest.wipe()
        plaintext.close()
    }
}

internal data class DomainStoredSecret(
    val recordKey: String,
    val ownerKey: String,
    val schemaVersion: Int,
    val revision: Long,
    val secret: OwnedSecret,
) : Closeable {
    override fun close() = secret.close()
}

internal sealed interface DomainMutation {
    data class Put(
        val kind: Int,
        val recordKey: String,
        val ownerKey: String,
        val schemaVersion: Int,
        val expectedRevision: Long,
        val plaintext: ByteArray,
    ) : DomainMutation

    data class Delete(
        val kind: Int,
        val recordKey: String,
        val expectedRevision: Long,
        val cascadeOwnerKey: String? = null,
    ) : DomainMutation
}

internal sealed interface RatchetMutation {
    val contactId: ByteArray
    val expectedRevision: Long

    class Put(
        override val contactId: ByteArray,
        override val expectedRevision: Long,
        val schemaVersion: Int,
        val plaintext: ByteArray,
        val purgePreviousSessionArtifacts: Boolean,
    ) : RatchetMutation

    class Delete(
        override val contactId: ByteArray,
        override val expectedRevision: Long,
    ) : RatchetMutation
}

/**
 * All values in encrypted_records are AES-256-GCM records. The only plaintext indices are hashes
 * of caller-provided random IDs and timestamps. Contact names and cryptographic state are never
 * accepted by an unencrypted API.
 */
class VaultRecordStore(
    context: Context,
    private val vault: VaultLockController,
) : Closeable {
    private val helper = VaultDatabase.open(context.applicationContext)
    private val recordCrypto = RecordCrypto()

    fun readRatchet(contactId: ByteArray): VersionedSecret? {
        val key = IdentifierCodec.contactKey(contactId)
        return vault.withDek { dek -> readSecret(dek, RecordKind.RATCHET, key) }
    }

    /** Inserts revision 1. Returns false if a ratchet already exists for this contact. */
    fun insertInitialRatchet(
        contactId: ByteArray,
        schemaVersion: Int,
        state: OwnedSecret,
    ): Boolean {
        val ownerKey = IdentifierCodec.contactKey(contactId)
        val plaintext = state.take()
        return try {
            vault.withDek { dek ->
                val encrypted = recordCrypto.encrypt(
                    dek,
                    RecordKind.RATCHET,
                    ownerKey,
                    schemaVersion,
                    1,
                    plaintext,
                )
                try {
                    insertRecord(helper.writableDatabase, RecordKind.RATCHET, ownerKey, ownerKey, encrypted)
                } finally {
                    encrypted.wipe()
                }
            }
        } finally {
            plaintext.wipe()
        }
    }

    /**
     * Atomically advances the ratchet and records ciphertext that may safely be retried after a
     * process crash. Nothing is committed if [expectedRatchetRevision] is stale.
     */
    @Throws(RatchetRevisionConflictException::class, VaultStorageException::class)
    fun commitOutbound(
        contactId: ByteArray,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        operationId: ByteArray,
        pendingCiphertext: ByteArray,
    ) = commitOutboundInternal(
        contactId,
        expectedRatchetRevision,
        ratchetSchemaVersion,
        newRatchetState,
        operationId,
        pendingCiphertext,
        null,
    )

    internal fun commitOutboundWithDomainMutation(
        contactId: ByteArray,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        operationId: ByteArray,
        pendingCiphertext: ByteArray,
        domainMutation: DomainMutation.Put,
    ) = commitOutboundInternal(
        contactId,
        expectedRatchetRevision,
        ratchetSchemaVersion,
        newRatchetState,
        operationId,
        pendingCiphertext,
        domainMutation,
    )

    private fun commitOutboundInternal(
        contactId: ByteArray,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        operationId: ByteArray,
        pendingCiphertext: ByteArray,
        domainMutation: DomainMutation.Put?,
    ) {
        try {
            require(expectedRatchetRevision > 0)
            require(newRatchetState.size <= RecordCrypto.MAX_RECORD_BYTES)
            val ownerKey = IdentifierCodec.contactKey(contactId)
            domainMutation?.let {
                require(it.expectedRevision > 0 && it.schemaVersion > 0)
                validateDomainCoordinates(it.kind, it.recordKey)
                validateDomainCoordinates(it.kind, it.ownerKey)
                require(it.ownerKey == ownerKey)
                require(it.plaintext.size <= RecordCrypto.MAX_RECORD_BYTES)
            }
            val operationKey = IdentifierCodec.operationKey(operationId)
            val nextRevision = Math.addExact(expectedRatchetRevision, 1)
            val contactBoundSize = PendingRecordCodec.encodedSize(contactId, pendingCiphertext.size)
            PendingRecordCodec.encodedSize(operationId, contactBoundSize)
            val ratchetPlaintext = newRatchetState.take()
            try {
                val contactBoundCiphertext = PendingRecordCodec.encode(contactId, pendingCiphertext)
                try {
                    val pendingPlaintext = PendingRecordCodec.encode(operationId, contactBoundCiphertext)
                    try {
                        vault.withDek { dek ->
                            val ratchet = recordCrypto.encrypt(
                                dek, RecordKind.RATCHET, ownerKey, ratchetSchemaVersion, nextRevision, ratchetPlaintext,
                            )
                            try {
                                val pending = recordCrypto.encrypt(
                                    dek,
                                    RecordKind.PENDING_OUTBOUND,
                                    operationKey,
                                    PENDING_SCHEMA_VERSION,
                                    nextRevision,
                                    pendingPlaintext,
                                )
                                try {
                                    val domain = domainMutation?.let { mutation ->
                                        recordCrypto.encrypt(
                                            dek,
                                            mutation.kind,
                                            mutation.recordKey,
                                            mutation.schemaVersion,
                                            Math.addExact(mutation.expectedRevision, 1),
                                            mutation.plaintext,
                                        )
                                    }
                                    try {
                                        inTransaction(helper.writableDatabase) { db ->
                                            if (!updateRatchet(db, ownerKey, expectedRatchetRevision, ratchet)) {
                                                throw RatchetRevisionConflictException()
                                            }
                                            if (domainMutation != null &&
                                                !updateDomainRecord(db, domainMutation, checkNotNull(domain))
                                            ) {
                                                throw RatchetRevisionConflictException()
                                            }
                                            if (!insertRecord(
                                                    db,
                                                    RecordKind.PENDING_OUTBOUND,
                                                    operationKey,
                                                    ownerKey,
                                                    pending,
                                                )
                                            ) {
                                                throw VaultStorageException("Pending outbound operation already exists")
                                            }
                                        }
                                    } finally {
                                        domain?.wipe()
                                    }
                                } finally {
                                    pending.wipe()
                                }
                            } finally {
                                ratchet.wipe()
                            }
                        }
                    } finally {
                        pendingPlaintext.wipe()
                    }
                } finally {
                    contactBoundCiphertext.wipe()
                }
            } finally {
                ratchetPlaintext.wipe()
            }
        } finally {
            newRatchetState.close()
        }
    }

    fun completeOutbound(operationId: ByteArray): Boolean {
        val key = IdentifierCodec.operationKey(operationId)
        return helper.writableDatabase.delete(
            TABLE_RECORDS,
            "kind=? AND record_key=?",
            arrayOf(RecordKind.PENDING_OUTBOUND.toString(), key),
        ) == 1
    }

    fun listPendingOutbound(limit: Int = MAX_PENDING_RESULTS): List<PendingOutbound> {
        require(limit in 1..MAX_PENDING_RESULTS)
        return vault.withDek { dek ->
            queryRecords(RecordKind.PENDING_OUTBOUND, limit).map { row ->
                try {
                    val decrypted = recordCrypto.decrypt(dek, RecordKind.PENDING_OUTBOUND, row.recordKey, row.encrypted)
                    try {
                        val (id, contactBoundCiphertext) = PendingRecordCodec.decode(decrypted)
                        try {
                            val (contactId, ciphertext) = PendingRecordCodec.decode(contactBoundCiphertext)
                            PendingOutbound(contactId, id, ciphertext, row.encrypted.revision)
                        } finally {
                            contactBoundCiphertext.wipe()
                        }
                    } finally {
                        decrypted.wipe()
                    }
                } finally {
                    row.encrypted.wipe()
                }
            }
        }
    }

    /**
     * Replay marker, new ratchet and encrypted pending-display plaintext share one SQLite commit.
     * A replay never advances state and never replaces the pending display.
     */
    fun commitInbound(
        contactId: ByteArray,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        messageId: ByteArray,
        ciphertextDigest: ByteArray,
        pendingPlaintext: OwnedSecret,
    ): AtomicInboundResult = commitInboundInternal(
        contactId,
        expectedRatchetRevision,
        ratchetSchemaVersion,
        newRatchetState,
        messageId,
        ciphertextDigest,
        pendingPlaintext,
        null,
    )

    internal fun commitInboundWithDomainMutation(
        contactId: ByteArray,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        messageId: ByteArray,
        ciphertextDigest: ByteArray,
        pendingPlaintext: OwnedSecret,
        domainMutation: DomainMutation.Put,
    ): AtomicInboundResult = commitInboundInternal(
        contactId,
        expectedRatchetRevision,
        ratchetSchemaVersion,
        newRatchetState,
        messageId,
        ciphertextDigest,
        pendingPlaintext,
        domainMutation,
    )

    private fun commitInboundInternal(
        contactId: ByteArray,
        expectedRatchetRevision: Long,
        ratchetSchemaVersion: Int,
        newRatchetState: OwnedSecret,
        messageId: ByteArray,
        ciphertextDigest: ByteArray,
        pendingPlaintext: OwnedSecret,
        domainMutation: DomainMutation.Put?,
    ): AtomicInboundResult {
        try {
            require(expectedRatchetRevision > 0)
            require(ciphertextDigest.size == CIPHERTEXT_DIGEST_BYTES)
            require(newRatchetState.size <= RecordCrypto.MAX_RECORD_BYTES)
            val ownerKey = IdentifierCodec.contactKey(contactId)
            domainMutation?.let {
                require(it.expectedRevision > 0 && it.schemaVersion > 0)
                validateDomainCoordinates(it.kind, it.recordKey)
                validateDomainCoordinates(it.kind, it.ownerKey)
                require(it.ownerKey == ownerKey)
                require(it.plaintext.size <= RecordCrypto.MAX_RECORD_BYTES)
            }
            val displayPayloadSize = Math.addExact(CIPHERTEXT_DIGEST_BYTES, pendingPlaintext.size)
            PendingRecordCodec.encodedSize(messageId, displayPayloadSize)
            val displayKey = IdentifierCodec.displayKey(messageId)
            val replayKey = IdentifierCodec.replayKey(contactId, messageId)
            val nextRevision = Math.addExact(expectedRatchetRevision, 1)
            val ratchetBytes = newRatchetState.take()
            try {
                val displayBytes = pendingPlaintext.take()
                try {
                    val boundDisplay = ByteArray(displayPayloadSize)
                    try {
                        ciphertextDigest.copyInto(boundDisplay)
                        displayBytes.copyInto(boundDisplay, CIPHERTEXT_DIGEST_BYTES)
                        val encodedDisplay = PendingRecordCodec.encode(messageId, boundDisplay)
                        try {
                            return vault.withDek { dek ->
                                val ratchet = recordCrypto.encrypt(
                                    dek, RecordKind.RATCHET, ownerKey, ratchetSchemaVersion, nextRevision, ratchetBytes,
                                )
                                try {
                                    val display = recordCrypto.encrypt(
                                        dek,
                                        RecordKind.PENDING_DISPLAY,
                                        displayKey,
                                        PENDING_SCHEMA_VERSION,
                                        nextRevision,
                                        encodedDisplay,
                                    )
                                    try {
                                        val domain = domainMutation?.let { mutation ->
                                            recordCrypto.encrypt(
                                                dek,
                                                mutation.kind,
                                                mutation.recordKey,
                                                mutation.schemaVersion,
                                                Math.addExact(mutation.expectedRevision, 1),
                                                mutation.plaintext,
                                            )
                                        }
                                        try {
                                            try {
                                                inTransaction(helper.writableDatabase) { db ->
                                                    if (!insertReplay(db, replayKey, ownerKey)) {
                                                        throw AbortInbound(AtomicInboundResult.REPLAY)
                                                    }
                                                    pruneReplayMarkers(
                                                        db,
                                                        ownerKey,
                                                        replayKey,
                                                        MAX_REPLAY_MARKERS_PER_CONTACT,
                                                    )
                                                    if (!updateRatchet(
                                                            db,
                                                            ownerKey,
                                                            expectedRatchetRevision,
                                                            ratchet,
                                                        )
                                                    ) {
                                                        throw AbortInbound(AtomicInboundResult.REVISION_CONFLICT)
                                                    }
                                                    if (domainMutation != null &&
                                                        !updateDomainRecord(db, domainMutation, checkNotNull(domain))
                                                    ) {
                                                        throw AbortInbound(AtomicInboundResult.REVISION_CONFLICT)
                                                    }
                                                    if (!insertRecord(
                                                            db,
                                                            RecordKind.PENDING_DISPLAY,
                                                            displayKey,
                                                            ownerKey,
                                                            display,
                                                        )
                                                    ) {
                                                        throw VaultStorageException("Pending display already exists")
                                                    }
                                                }
                                                AtomicInboundResult.COMMITTED
                                            } catch (abort: AbortInbound) {
                                                abort.result
                                            }
                                        } finally {
                                            domain?.wipe()
                                        }
                                    } finally {
                                        display.wipe()
                                    }
                                } finally {
                                    ratchet.wipe()
                                }
                            }
                        } finally {
                            encodedDisplay.wipe()
                        }
                    } finally {
                        boundDisplay.wipe()
                    }
                } finally {
                    displayBytes.wipe()
                }
            } finally {
                ratchetBytes.wipe()
            }
        } finally {
            newRatchetState.close()
            pendingPlaintext.close()
        }
    }

    fun isReplay(contactId: ByteArray, messageId: ByteArray): Boolean {
        val key = IdentifierCodec.replayKey(contactId, messageId)
        return vault.withDek {
            helper.readableDatabase.query(
                TABLE_REPLAY,
                arrayOf("1"),
                "replay_key=?",
                arrayOf(key),
                null,
                null,
                null,
                "1",
            ).use { cursor -> cursor.moveToFirst() }
        }
    }

    @androidx.annotation.VisibleForTesting
    internal fun insertReplayMarkerForTesting(
        contactId: ByteArray,
        messageId: ByteArray,
        maxRecords: Int,
    ): Boolean {
        require(maxRecords > 0)
        val ownerKey = IdentifierCodec.contactKey(contactId)
        val replayKey = IdentifierCodec.replayKey(contactId, messageId)
        return inTransaction(helper.writableDatabase) { db ->
            if (!insertReplay(db, replayKey, ownerKey)) return@inTransaction false
            pruneReplayMarkers(db, ownerKey, replayKey, maxRecords)
            true
        }
    }

    @androidx.annotation.VisibleForTesting
    internal fun replayMarkerCountForTesting(contactId: ByteArray): Int {
        val ownerKey = IdentifierCodec.contactKey(contactId)
        helper.readableDatabase.rawQuery(
            "SELECT COUNT(*) FROM $TABLE_REPLAY WHERE owner_key=?",
            arrayOf(ownerKey),
        ).use { cursor ->
            check(cursor.moveToFirst())
            return cursor.getInt(0)
        }
    }

    fun readPendingDisplay(contactId: ByteArray, messageId: ByteArray): PendingDisplay? {
        val key = IdentifierCodec.displayKey(messageId)
        val expectedOwnerKey = IdentifierCodec.contactKey(contactId)
        return vault.withDek { dek ->
            val row = queryRecord(RecordKind.PENDING_DISPLAY, key) ?: return@withDek null
            try {
                if (row.ownerKey != expectedOwnerKey) {
                    throw VaultCorruptException("Pending display owner does not match its contact")
                }
                val encoded = recordCrypto.decrypt(dek, RecordKind.PENDING_DISPLAY, key, row.encrypted)
                try {
                    val (storedId, boundDisplay) = PendingRecordCodec.decode(encoded)
                    try {
                        if (!storedId.contentEquals(messageId) ||
                            boundDisplay.size < CIPHERTEXT_DIGEST_BYTES
                        ) {
                            storedId.wipe()
                            throw VaultCorruptException("Pending display binding is invalid")
                        }
                        val digest = boundDisplay.copyOfRange(0, CIPHERTEXT_DIGEST_BYTES)
                        val plaintext = boundDisplay.copyOfRange(CIPHERTEXT_DIGEST_BYTES, boundDisplay.size)
                        PendingDisplay(storedId, digest, OwnedSecret(plaintext), row.encrypted.revision)
                    } finally {
                        boundDisplay.wipe()
                    }
                } finally {
                    encoded.wipe()
                }
            } finally {
                row.encrypted.wipe()
            }
        }
    }

    fun deletePendingDisplay(messageId: ByteArray): Boolean {
        val key = IdentifierCodec.displayKey(messageId)
        return helper.writableDatabase.delete(
            TABLE_RECORDS,
            "kind=? AND record_key=?",
            arrayOf(RecordKind.PENDING_DISPLAY.toString(), key),
        ) == 1
    }

    /** Deletes encrypted plaintext handoff records that exceeded the crash-recovery window. */
    fun purgePendingDisplaysCreatedAtOrBefore(cutoffEpochMillis: Long): Int {
        require(cutoffEpochMillis >= 0)
        return helper.writableDatabase.delete(
            TABLE_RECORDS,
            "kind=? AND created_at<=?",
            arrayOf(RecordKind.PENDING_DISPLAY.toString(), cutoffEpochMillis.toString()),
        )
    }

    /** Deletes ratchet, all pending operations and replay markers for one random contact ID. */
    fun deleteContact(contactId: ByteArray) {
        val ownerKey = IdentifierCodec.contactKey(contactId)
        vault.withDek {
            inTransaction(helper.writableDatabase) { db ->
                db.delete(TABLE_RECORDS, "owner_key=?", arrayOf(ownerKey))
                db.delete(TABLE_REPLAY, "owner_key=?", arrayOf(ownerKey))
            }
        }
    }

    fun destroyAll() {
        val db = helper.writableDatabase
        inTransaction(db) {
            it.delete(TABLE_RECORDS, null, null)
            it.delete(TABLE_REPLAY, null, null)
        }
        db.execSQL("VACUUM")
    }

    internal fun readDomainRecord(kind: Int, recordKey: String): DomainStoredSecret? {
        validateDomainCoordinates(kind, recordKey)
        return vault.withDek { dek ->
            val row = queryRecord(kind, recordKey) ?: return@withDek null
            try {
                val plaintext = recordCrypto.decrypt(dek, kind, recordKey, row.encrypted)
                DomainStoredSecret(
                    row.recordKey,
                    row.ownerKey,
                    row.encrypted.schemaVersion,
                    row.encrypted.revision,
                    OwnedSecret(plaintext),
                )
            } finally {
                row.encrypted.wipe()
            }
        }
    }

    internal fun listDomainRecords(
        kind: Int,
        limit: Int,
        newestFirst: Boolean = false,
    ): List<DomainStoredSecret> {
        require(kind > 0)
        require(limit in 1..MAX_DOMAIN_RESULTS)
        return vault.withDek { dek ->
            val rows = queryRecords(kind, limit, newestFirst)
            val result = ArrayList<DomainStoredSecret>(rows.size)
            try {
                rows.forEach { row ->
                    val plaintext = recordCrypto.decrypt(dek, kind, row.recordKey, row.encrypted)
                    result += DomainStoredSecret(
                        row.recordKey,
                        row.ownerKey,
                        row.encrypted.schemaVersion,
                        row.encrypted.revision,
                        OwnedSecret(plaintext),
                    )
                }
                result
            } catch (error: Exception) {
                result.forEach { it.close() }
                throw error
            } finally {
                rows.forEach { it.encrypted.wipe() }
            }
        }
    }

    internal fun countDomainRecords(kind: Int): Int {
        require(kind > 0)
        return helper.readableDatabase.rawQuery(
            "SELECT COUNT(*) FROM $TABLE_RECORDS WHERE kind=?",
            arrayOf(kind.toString()),
        ).use { cursor ->
            check(cursor.moveToFirst())
            cursor.getInt(0)
        }
    }

    /** Applies domain mutations and an optional ratchet mutation in one SQLite transaction. */
    internal fun applyDomainMutations(
        mutations: List<DomainMutation>,
        ratchetMutation: RatchetMutation? = null,
    ): Boolean {
        require(mutations.isNotEmpty() && mutations.size <= MAX_DOMAIN_MUTATIONS)
        mutations.forEach {
            when (it) {
                is DomainMutation.Put -> {
                    validateDomainCoordinates(it.kind, it.recordKey)
                    validateDomainCoordinates(it.kind, it.ownerKey)
                    require(it.schemaVersion > 0 && it.expectedRevision >= 0)
                }
                is DomainMutation.Delete -> {
                    validateDomainCoordinates(it.kind, it.recordKey)
                    require(it.expectedRevision > 0)
                    it.cascadeOwnerKey?.let { owner -> validateDomainCoordinates(it.kind, owner) }
                }
            }
        }
        ratchetMutation?.let { mutation ->
            require(mutation.contactId.isNotEmpty())
            when (mutation) {
                is RatchetMutation.Put -> require(
                    mutation.expectedRevision >= 0 &&
                        mutation.schemaVersion > 0 &&
                        mutation.plaintext.isNotEmpty(),
                )
                is RatchetMutation.Delete -> require(mutation.expectedRevision > 0)
            }
        }
        return vault.withDek { dek ->
            val encrypted = ArrayList<Pair<DomainMutation, EncryptedRecord?>>(mutations.size)
            var encryptedRatchet: EncryptedRecord? = null
            val ratchetOwnerKey = ratchetMutation?.let { IdentifierCodec.contactKey(it.contactId) }
            try {
                mutations.forEach { mutation ->
                    val record = if (mutation is DomainMutation.Put) {
                        val nextRevision = Math.addExact(mutation.expectedRevision, 1)
                        recordCrypto.encrypt(
                            dek,
                            mutation.kind,
                            mutation.recordKey,
                            mutation.schemaVersion,
                            nextRevision,
                            mutation.plaintext,
                        )
                    } else {
                        null
                    }
                    encrypted += mutation to record
                }
                encryptedRatchet = (ratchetMutation as? RatchetMutation.Put)?.let { mutation ->
                    recordCrypto.encrypt(
                        dek = dek,
                        kind = RecordKind.RATCHET,
                        recordKey = checkNotNull(ratchetOwnerKey),
                        schemaVersion = mutation.schemaVersion,
                        revision = Math.addExact(mutation.expectedRevision, 1),
                        plaintext = mutation.plaintext,
                    )
                }
                try {
                    inTransaction(helper.writableDatabase) { db ->
                        encrypted.forEach { (mutation, record) ->
                            when (mutation) {
                                is DomainMutation.Put -> {
                                    val encryptedRecord = checkNotNull(record)
                                    val applied = if (mutation.expectedRevision == 0L) {
                                        insertRecord(
                                            db,
                                            mutation.kind,
                                            mutation.recordKey,
                                            mutation.ownerKey,
                                            encryptedRecord,
                                        )
                                    } else {
                                        updateDomainRecord(db, mutation, encryptedRecord)
                                    }
                                    if (!applied) throw AbortDomainMutation()
                                }
                                is DomainMutation.Delete -> {
                                    val deleted = db.delete(
                                        TABLE_RECORDS,
                                        "kind=? AND record_key=? AND revision=?",
                                        arrayOf(
                                            mutation.kind.toString(),
                                            mutation.recordKey,
                                            mutation.expectedRevision.toString(),
                                        ),
                                    ) == 1
                                    if (!deleted) throw AbortDomainMutation()
                                    mutation.cascadeOwnerKey?.let { ownerKey ->
                                        db.delete(TABLE_RECORDS, "owner_key=?", arrayOf(ownerKey))
                                        db.delete(TABLE_REPLAY, "owner_key=?", arrayOf(ownerKey))
                                    }
                                }
                            }
                        }
                        ratchetMutation?.let { mutation ->
                            val ownerKey = checkNotNull(ratchetOwnerKey)
                            when (mutation) {
                                is RatchetMutation.Put -> {
                                    val record = checkNotNull(encryptedRatchet)
                                    val applied = if (mutation.expectedRevision == 0L) {
                                        insertRecord(
                                            db,
                                            RecordKind.RATCHET,
                                            ownerKey,
                                            ownerKey,
                                            record,
                                        )
                                    } else {
                                        updateRatchet(db, ownerKey, mutation.expectedRevision, record)
                                    }
                                    if (!applied) throw AbortDomainMutation()
                                    if (mutation.purgePreviousSessionArtifacts) {
                                        purgeSessionArtifacts(db, ownerKey)
                                    }
                                }
                                is RatchetMutation.Delete -> {
                                    val deleted = db.delete(
                                        TABLE_RECORDS,
                                        "kind=? AND record_key=? AND revision=?",
                                        arrayOf(
                                            RecordKind.RATCHET.toString(),
                                            ownerKey,
                                            mutation.expectedRevision.toString(),
                                        ),
                                    ) == 1
                                    if (!deleted) throw AbortDomainMutation()
                                    purgeSessionArtifacts(db, ownerKey)
                                }
                            }
                        }
                    }
                    true
                } catch (_: AbortDomainMutation) {
                    false
                }
            } finally {
                encrypted.forEach { it.second?.wipe() }
                encryptedRatchet?.wipe()
            }
        }
    }

    override fun close() {
        helper.close()
    }

    private fun readSecret(dek: ByteArray, kind: Int, key: String): VersionedSecret? {
        val row = queryRecord(kind, key) ?: return null
        return try {
            val plaintext = recordCrypto.decrypt(dek, kind, key, row.encrypted)
            VersionedSecret(row.encrypted.schemaVersion, row.encrypted.revision, OwnedSecret(plaintext))
        } finally {
            row.encrypted.wipe()
        }
    }

    private fun queryRecord(kind: Int, key: String): StoredRow? {
        helper.readableDatabase.query(
            TABLE_RECORDS,
            RECORD_COLUMNS,
            "kind=? AND record_key=?",
            arrayOf(kind.toString(), key),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            return if (cursor.moveToFirst()) cursor.toStoredRow() else null
        }
    }

    private fun queryRecords(kind: Int, limit: Int, newestFirst: Boolean = false): List<StoredRow> {
        helper.readableDatabase.query(
            TABLE_RECORDS,
            RECORD_COLUMNS,
            "kind=?",
            arrayOf(kind.toString()),
            null,
            null,
            if (newestFirst) "created_at DESC" else "created_at ASC",
            limit.toString(),
        ).use { cursor ->
            val result = ArrayList<StoredRow>(cursor.count.coerceAtMost(limit))
            return try {
                while (cursor.moveToNext()) result += cursor.toStoredRow()
                result
            } catch (error: Exception) {
                result.forEach { it.encrypted.wipe() }
                throw error
            }
        }
    }

    private fun Cursor.toStoredRow(): StoredRow {
        val key = getString(getColumnIndexOrThrow("record_key"))
        val ownerKey = getString(getColumnIndexOrThrow("owner_key"))
        val schemaVersion = getInt(getColumnIndexOrThrow("schema_version"))
        val revision = getLong(getColumnIndexOrThrow("revision"))
        val nonce = getBlob(getColumnIndexOrThrow("nonce"))
        val ciphertext = getBlob(getColumnIndexOrThrow("ciphertext"))
        if (key.length !in 1..MAX_STORED_KEY_CHARS || ownerKey.length !in 1..MAX_STORED_KEY_CHARS ||
            schemaVersion <= 0 || revision <= 0
        ) {
            throw VaultCorruptException("Encrypted record metadata is invalid")
        }
        return StoredRow(key, ownerKey, EncryptedRecord(schemaVersion, revision, nonce, ciphertext))
    }

    private fun insertRecord(
        db: SQLiteDatabase,
        kind: Int,
        key: String,
        ownerKey: String,
        record: EncryptedRecord,
    ): Boolean {
        val now = System.currentTimeMillis()
        val values = recordValues(record).apply {
            put("kind", kind)
            put("record_key", key)
            put("owner_key", ownerKey)
            put("created_at", now)
            put("updated_at", now)
        }
        return db.insertWithOnConflict(TABLE_RECORDS, null, values, SQLiteDatabase.CONFLICT_IGNORE) != -1L
    }

    private fun updateRatchet(
        db: SQLiteDatabase,
        key: String,
        expectedRevision: Long,
        record: EncryptedRecord,
    ): Boolean {
        val values = recordValues(record).apply { put("updated_at", System.currentTimeMillis()) }
        return db.update(
            TABLE_RECORDS,
            values,
            "kind=? AND record_key=? AND revision=?",
            arrayOf(RecordKind.RATCHET.toString(), key, expectedRevision.toString()),
        ) == 1
    }

    private fun updateDomainRecord(
        db: SQLiteDatabase,
        mutation: DomainMutation.Put,
        record: EncryptedRecord,
    ): Boolean {
        val values = recordValues(record).apply {
            put("owner_key", mutation.ownerKey)
            put("updated_at", System.currentTimeMillis())
        }
        return db.update(
            TABLE_RECORDS,
            values,
            "kind=? AND record_key=? AND revision=?",
            arrayOf(mutation.kind.toString(), mutation.recordKey, mutation.expectedRevision.toString()),
        ) == 1
    }

    private fun recordValues(record: EncryptedRecord) = ContentValues().apply {
        put("schema_version", record.schemaVersion)
        put("revision", record.revision)
        put("nonce", record.nonce)
        put("ciphertext", record.ciphertext)
    }

    private fun insertReplay(db: SQLiteDatabase, key: String, ownerKey: String): Boolean {
        val values = ContentValues().apply {
            put("replay_key", key)
            put("owner_key", ownerKey)
            put("received_at", System.currentTimeMillis())
        }
        return db.insertWithOnConflict(TABLE_REPLAY, null, values, SQLiteDatabase.CONFLICT_IGNORE) != -1L
    }

    private fun pruneReplayMarkers(
        db: SQLiteDatabase,
        ownerKey: String,
        currentReplayKey: String,
        maxRecords: Int,
    ) {
        require(maxRecords > 0)
        db.delete(
            TABLE_REPLAY,
            """
            owner_key=? AND replay_key NOT IN (
                SELECT replay_key FROM $TABLE_REPLAY
                WHERE owner_key=?
                ORDER BY (replay_key=?) DESC, received_at DESC, replay_key DESC
                LIMIT $maxRecords
            )
            """.trimIndent(),
            arrayOf(ownerKey, ownerKey, currentReplayKey),
        )
    }

    private fun purgeSessionArtifacts(db: SQLiteDatabase, ownerKey: String) {
        db.delete(
            TABLE_RECORDS,
            "owner_key=? AND kind IN (?,?)",
            arrayOf(
                ownerKey,
                RecordKind.PENDING_OUTBOUND.toString(),
                RecordKind.PENDING_DISPLAY.toString(),
            ),
        )
        db.delete(TABLE_REPLAY, "owner_key=?", arrayOf(ownerKey))
    }

    private inline fun <T> inTransaction(db: SQLiteDatabase, block: (SQLiteDatabase) -> T): T {
        db.beginTransaction()
        return try {
            val result = block(db)
            db.setTransactionSuccessful()
            result
        } finally {
            db.endTransaction()
        }
    }

    private fun validateDomainCoordinates(kind: Int, key: String) {
        require(kind > 0)
        require(key.length in 1..MAX_STORED_KEY_CHARS && key.all { it in '0'..'9' || it in 'a'..'f' })
    }

    private data class StoredRow(
        val recordKey: String,
        val ownerKey: String,
        val encrypted: EncryptedRecord,
    )
    private class AbortInbound(val result: AtomicInboundResult) : RuntimeException() {
        override fun fillInStackTrace(): Throwable = this
    }
    private class AbortDomainMutation : RuntimeException() {
        override fun fillInStackTrace(): Throwable = this
    }

    private object RecordKind {
        const val RATCHET = 1
        const val PENDING_OUTBOUND = 2
        const val PENDING_DISPLAY = 3
    }

    companion object {
        private const val TABLE_RECORDS = "encrypted_records"
        private const val TABLE_REPLAY = "replay_ids"
        private const val PENDING_SCHEMA_VERSION = 1
        private const val CIPHERTEXT_DIGEST_BYTES = 32
        private const val MAX_PENDING_RESULTS = 256
        private const val MAX_DOMAIN_RESULTS = 1_024
        private const val MAX_DOMAIN_MUTATIONS = 8
        private const val MAX_REPLAY_MARKERS_PER_CONTACT = 8_192
        private const val MAX_STORED_KEY_CHARS = 128
        private val RECORD_COLUMNS = arrayOf(
            "record_key", "owner_key", "schema_version", "revision", "nonce", "ciphertext",
        )
    }
}
