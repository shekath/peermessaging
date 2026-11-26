package com.cipher.p2p.storage

import android.content.ContentValues
import android.content.Context
import com.cipher.p2p.security.KeystoreVault
import com.cipher.p2p.security.SecretFile
import com.cipher.p2p.security.wipe
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SQLiteOpenHelper

/**
 * Layer 2 — encrypted at rest.
 *
 * SQLCipher (AES-256, per-page HMAC) with a random 256-bit key. The key itself is wrapped
 * by the hardware Keystore, so the database file is useless off-device. Secure-delete and
 * no journal-on-disk keep deleted messages from lingering in free pages.
 */
class SecureDatabase private constructor(context: Context, key: ByteArray) :
    SQLiteOpenHelper(context, NAME, key, null, VERSION, 0, null, null, true) {

    override fun onConfigure(db: SQLiteDatabase) {
        db.rawExecSQL("PRAGMA cipher_memory_security = ON")
        db.rawExecSQL("PRAGMA secure_delete = ON")
        db.rawExecSQL("PRAGMA journal_mode = MEMORY")
        db.rawExecSQL("PRAGMA foreign_keys = ON")
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE kv (k TEXT PRIMARY KEY, v BLOB NOT NULL)")
        db.execSQL("CREATE TABLE identities (address TEXT PRIMARY KEY, identity_key BLOB NOT NULL, verified INTEGER NOT NULL DEFAULT 0)")
        db.execSQL("CREATE TABLE prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL)")
        db.execSQL("CREATE TABLE signed_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL)")
        db.execSQL("CREATE TABLE kyber_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
        db.execSQL("CREATE TABLE sessions (address TEXT NOT NULL, device INTEGER NOT NULL, record BLOB NOT NULL, PRIMARY KEY(address, device))")
        db.execSQL("CREATE TABLE sender_keys (address TEXT NOT NULL, device INTEGER NOT NULL, distribution TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY(address, device, distribution))")
        db.execSQL("CREATE TABLE invites (secret BLOB PRIMARY KEY, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
        db.execSQL("CREATE TABLE contacts (address TEXT PRIMARY KEY, name TEXT NOT NULL, transports BLOB, added_at INTEGER NOT NULL)")
        db.execSQL("CREATE TABLE messages (id TEXT PRIMARY KEY, address TEXT NOT NULL, outgoing INTEGER NOT NULL, body BLOB NOT NULL, ts INTEGER NOT NULL, state INTEGER NOT NULL, expires_at INTEGER)")
        db.execSQL("CREATE TABLE outbox (id TEXT PRIMARY KEY, address TEXT NOT NULL, envelope BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL)")
        db.execSQL("CREATE TABLE seen_envelopes (hash BLOB PRIMARY KEY, ts INTEGER NOT NULL)") // replay guard
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    // --- tiny typed helpers used by the protocol store ---
    fun putBlob(table: String, keyCol: String, key: Any, valueCol: String, value: ByteArray, extra: ContentValues? = null) {
        val cv = ContentValues().apply {
            when (key) { is Int -> put(keyCol, key); is Long -> put(keyCol, key); else -> put(keyCol, key.toString()) }
            put(valueCol, value); extra?.let { putAll(it) }
        }
        writableDatabase.insertWithOnConflict(table, null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun getBlob(table: String, keyCol: String, key: Any, valueCol: String): ByteArray? =
        readableDatabase.rawQuery("SELECT $valueCol FROM $table WHERE $keyCol = ?", arrayOf(key.toString())).use {
            if (it.moveToFirst()) it.getBlob(0) else null
        }

    fun delete(table: String, keyCol: String, key: Any) =
        writableDatabase.delete(table, "$keyCol = ?", arrayOf(key.toString()))

    companion object {
        private const val NAME = "cipher.db"
        private const val VERSION = 1
        @Volatile private var instance: SecureDatabase? = null

        fun get(context: Context, vault: KeystoreVault): SecureDatabase = instance ?: synchronized(this) {
            instance ?: run {
                System.loadLibrary("sqlcipher")
                val key = SecretFile(context, vault, "db_key").getOrCreate(32)
                SecureDatabase(context.applicationContext, key).also { key.wipe(); instance = it }
            }
        }
    }
}
