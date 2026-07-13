// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin.database

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import androidx.core.database.getStringOrNull
import androidx.core.database.sqlite.transaction
import helium314.keyboard.latin.utils.Log
import java.io.File

class Database private constructor(context: Context, name: String = NAME) : SQLiteOpenHelper(context, name, null, VERSION) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(ClipboardDao.CREATE_TABLE)
        onUpgrade(db, 0, VERSION)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion <= 2) {
            db.execSQL(ClipboardDao.ADD_FILE_COLUMN)
            db.execSQL(ClipboardDao.ADD_MIME_TYPE_COLUMN)
        }
        if (oldVersion < 4) {
            db.execSQL("DROP TABLE IF EXISTS GESTURE_DATA")
        }
    }

    companion object {
        private val TAG = Database::class.java.simpleName
        private const val VERSION = 4
        const val NAME = "cipherboard.db"
        private var instance: Database? = null
        fun getInstance(context: Context): Database {
            if (instance == null)
                instance = Database(context)
            return instance!!
        }

        // needs to be in sync with db version
        fun copyFromDb(file: File, context: Context) {
            if (!file.exists())
                return
            val otherDb = Database(context, file.name) // this upgrades the DB if necessary
            val clipDao = ClipboardDao.getInstance(context) // insert to dao because of cache
            val db = getInstance(context)

            try {
                db.writableDatabase.transaction {
                    if (clipDao == null) {
                        Log.e(TAG, "can't transfer clipboard data because ClipboardDao is null")
                    } else {
                        otherDb.readableDatabase.rawQuery("SELECT TIMESTAMP, PINNED, TEXT, FILE, MIME_TYPE FROM CLIPBOARD", null)
                            .use {
                                clipDao.clear()
                                while (it.moveToNext()) {
                                    clipDao.insertNewEntry(
                                        it.getLong(0),
                                        it.getInt(1) != 0,
                                        it.getStringOrNull(2),
                                        it.getStringOrNull(3),
                                        it.getStringOrNull(4)?.split("§"),
                                        null
                                    )
                                }
                            }
                    }
                }
            } finally {
                otherDb.close()
                file.delete()
            }
        }
    }
}
