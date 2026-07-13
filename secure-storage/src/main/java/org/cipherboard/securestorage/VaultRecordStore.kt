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
    val operationId: ByteArray,
    val ciphertext: ByteArray,
    val revision: Long,
)

data class PendingDisplay(
    val messageId: ByteArray,
    val plaintext: OwnedSecret,
    val revision: Long,
) : Closeable {
    override fun close() {
        messageId.wipe()
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
    ) {
        require(expectedRatchetRevision > 0)
        val ownerKey = IdentifierCodec.contactKey(contactId)
        val operationKey = IdentifierCodec.operationKey(operationId)
        val nextRevision = Math.addExact(expectedRatchetRevision, 1)
        val ratchetPlaintext = newRatchetState.take()
        val pendingPlaintext = PendingRecordCodec.encode(operationId, pendingCiphertext)
        try {
            vault.withDek { dek ->
                val ratchet = recordCrypto.encrypt(
                    dek, RecordKind.RATCHET, ownerKey, ratchetSchemaVersion, nextRevision, ratchetPlaintext,
                )
                val pending = recordCrypto.encrypt(
                    dek, RecordKind.PENDING_OUTBOUND, operationKey, PENDING_SCHEMA_VERSION, nextRevision, pendingPlaintext,
                )
                try {
                    inTransaction(helper.writableDatabase) { db ->
                        if (!updateRatchet(db, ownerKey, expectedRatchetRevision, ratchet)) {
                            throw RatchetRevisionConflictException()
                        }
                        if (!insertRecord(db, RecordKind.PENDING_OUTBOUND, operationKey, ownerKey, pending)) {
                            throw VaultStorageException("Pending outbound operation already exists")
                        }
                    }
                } finally {
                    ratchet.wipe()
                    pending.wipe()
                }
            }
        } finally {
            ratchetPlaintext.wipe()
            pendingPlaintext.wipe()
        }
    }

    fun completeOutbound(operationId: ByteArray): Boolean {
        val key = IdentifierCodec.operationKey(operationId)
        return vault.withDek {
            helper.writableDatabase.delete(
                TABLE_RECORDS,
                "kind=? AND record_key=?",
                arrayOf(RecordKind.PENDING_OUTBOUND.toString(), key),
            ) == 1
        }
    }

    fun listPendingOutbound(limit: Int = MAX_PENDING_RESULTS): List<PendingOutbound> {
        require(limit in 1..MAX_PENDING_RESULTS)
        return vault.withDek { dek ->
            queryRecords(RecordKind.PENDING_OUTBOUND, limit).map { row ->
                try {
                    val decrypted = recordCrypto.decrypt(dek, RecordKind.PENDING_OUTBOUND, row.recordKey, row.encrypted)
                    try {
                        val (id, ciphertext) = PendingRecordCodec.decode(decrypted)
                        PendingOutbound(id, ciphertext, row.encrypted.revision)
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
        pendingPlaintext: OwnedSecret,
    ): AtomicInboundResult {
        require(expectedRatchetRevision > 0)
        val ownerKey = IdentifierCodec.contactKey(contactId)
        val displayKey = IdentifierCodec.displayKey(messageId)
        val replayKey = IdentifierCodec.replayKey(contactId, messageId)
        val nextRevision = Math.addExact(expectedRatchetRevision, 1)
        val ratchetBytes = newRatchetState.take()
        val displayBytes = pendingPlaintext.take()
        val encodedDisplay = PendingRecordCodec.encode(messageId, displayBytes)
        try {
            return vault.withDek { dek ->
                val ratchet = recordCrypto.encrypt(
                    dek, RecordKind.RATCHET, ownerKey, ratchetSchemaVersion, nextRevision, ratchetBytes,
                )
                val display = recordCrypto.encrypt(
                    dek, RecordKind.PENDING_DISPLAY, displayKey, PENDING_SCHEMA_VERSION, nextRevision, encodedDisplay,
                )
                try {
                    try {
                        inTransaction(helper.writableDatabase) { db ->
                            if (!insertReplay(db, replayKey, ownerKey)) {
                                throw AbortInbound(AtomicInboundResult.REPLAY)
                            }
                            if (!updateRatchet(db, ownerKey, expectedRatchetRevision, ratchet)) {
                                throw AbortInbound(AtomicInboundResult.REVISION_CONFLICT)
                            }
                            if (!insertRecord(db, RecordKind.PENDING_DISPLAY, displayKey, ownerKey, display)) {
                                throw VaultStorageException("Pending display already exists")
                            }
                        }
                        AtomicInboundResult.COMMITTED
                    } catch (abort: AbortInbound) {
                        abort.result
                    }
                } finally {
                    ratchet.wipe()
                    display.wipe()
                }
            }
        } finally {
            ratchetBytes.wipe()
            displayBytes.wipe()
            encodedDisplay.wipe()
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

    fun readPendingDisplay(messageId: ByteArray): PendingDisplay? {
        val key = IdentifierCodec.displayKey(messageId)
        return vault.withDek { dek ->
            val secret = readSecret(dek, RecordKind.PENDING_DISPLAY, key) ?: return@withDek null
            val encoded = secret.secret.take()
            try {
                val (storedId, plaintext) = PendingRecordCodec.decode(encoded)
                PendingDisplay(storedId, OwnedSecret(plaintext), secret.revision)
            } finally {
                encoded.wipe()
                secret.close()
            }
        }
    }

    fun deletePendingDisplay(messageId: ByteArray): Boolean {
        val key = IdentifierCodec.displayKey(messageId)
        return vault.withDek {
            helper.writableDatabase.delete(
                TABLE_RECORDS,
                "kind=? AND record_key=?",
                arrayOf(RecordKind.PENDING_DISPLAY.toString(), key),
            ) == 1
        }
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

    internal fun listDomainRecords(kind: Int, limit: Int): List<DomainStoredSecret> {
        require(kind > 0)
        require(limit in 1..MAX_DOMAIN_RESULTS)
        return vault.withDek { dek ->
            val rows = queryRecords(kind, limit)
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

    private fun queryRecords(kind: Int, limit: Int): List<StoredRow> {
        helper.readableDatabase.query(
            TABLE_RECORDS,
            RECORD_COLUMNS,
            "kind=?",
            arrayOf(kind.toString()),
            null,
            null,
            "created_at ASC",
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
        private const val MAX_PENDING_RESULTS = 256
        private const val MAX_DOMAIN_RESULTS = 1_024
        private const val MAX_DOMAIN_MUTATIONS = 8
        private const val MAX_STORED_KEY_CHARS = 128
        private val RECORD_COLUMNS = arrayOf(
            "record_key", "owner_key", "schema_version", "revision", "nonce", "ciphertext",
        )
    }
}
