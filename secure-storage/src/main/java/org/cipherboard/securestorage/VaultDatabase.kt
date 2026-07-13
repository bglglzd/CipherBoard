package org.cipherboard.securestorage

import android.content.Context
import android.content.ContextWrapper
import android.database.DatabaseErrorHandler
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.File

internal class VaultDatabase private constructor(context: Context) :
    SQLiteOpenHelper(NoBackupDatabaseContext(context), DATABASE_NAME, null, DATABASE_VERSION) {

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
        db.rawQuery("PRAGMA secure_delete=ON", null).use { it.moveToFirst() }
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE encrypted_records (
                kind INTEGER NOT NULL,
                record_key TEXT NOT NULL,
                owner_key TEXT NOT NULL,
                schema_version INTEGER NOT NULL CHECK(schema_version > 0),
                revision INTEGER NOT NULL CHECK(revision > 0),
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(kind, record_key)
            ) WITHOUT ROWID
            """.trimIndent(),
        )
        db.execSQL(
            "CREATE INDEX encrypted_records_owner ON encrypted_records(owner_key, kind)",
        )
        db.execSQL(
            """
            CREATE TABLE replay_ids (
                replay_key TEXT PRIMARY KEY NOT NULL,
                owner_key TEXT NOT NULL,
                received_at INTEGER NOT NULL
            ) WITHOUT ROWID
            """.trimIndent(),
        )
        db.execSQL("CREATE INDEX replay_ids_owner ON replay_ids(owner_key)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        throw IllegalStateException("Vault database migration is required: $oldVersion -> $newVersion")
    }

    companion object {
        private const val DATABASE_NAME = "cipherboard_vault.db"
        private const val DATABASE_VERSION = 1

        fun open(context: Context): VaultDatabase {
            return VaultDatabase(context.requireCredentialProtectedStorage())
        }
    }
}

/** Makes SQLiteOpenHelper place the database in noBackupFilesDir. */
private class NoBackupDatabaseContext(base: Context) : ContextWrapper(base) {
    private val databaseDirectory = File(noBackupFilesDir, "cipherboard_vault").apply { mkdirs() }

    override fun getDatabasePath(name: String): File = File(databaseDirectory, name)

    override fun openOrCreateDatabase(
        name: String,
        mode: Int,
        factory: SQLiteDatabase.CursorFactory?,
    ): SQLiteDatabase = SQLiteDatabase.openOrCreateDatabase(getDatabasePath(name), factory)

    override fun openOrCreateDatabase(
        name: String,
        mode: Int,
        factory: SQLiteDatabase.CursorFactory?,
        errorHandler: DatabaseErrorHandler?,
    ): SQLiteDatabase = if (errorHandler == null) {
        SQLiteDatabase.openOrCreateDatabase(getDatabasePath(name), factory)
    } else {
        SQLiteDatabase.openDatabase(
            getDatabasePath(name).path,
            factory,
            SQLiteDatabase.CREATE_IF_NECESSARY,
            errorHandler,
        )
    }

    override fun deleteDatabase(name: String): Boolean = SQLiteDatabase.deleteDatabase(getDatabasePath(name))
}
