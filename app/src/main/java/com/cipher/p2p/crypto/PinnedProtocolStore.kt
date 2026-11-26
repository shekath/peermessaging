package com.cipher.p2p.crypto

import android.content.ContentValues
import com.cipher.p2p.identity.IdentityManager
import com.cipher.p2p.storage.SecureDatabase
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.ecc.ECPublicKey
import java.util.UUID

/**
 * Layer 5 — the libsignal state store, persisted in the encrypted database.
 *
 * Key hardening vs. a default store: **no trust on first use.** An identity is trusted only
 * if it was pinned through a verified invite (or an in-person QR safety-number check). A
 * message from any other key is rejected before decryption, so a network attacker can't
 * slip in as a new contact or silently replace an existing one's key.
 *
 * Note: libsignal's store interfaces change between releases. This targets 0.64.x; if you
 * bump the version, adjust method signatures to match (the logic stays the same).
 */
class PinnedProtocolStore(
    private val identity: IdentityManager,
    private val db: SecureDatabase,
) : SignalProtocolStore {

    private fun key(a: SignalProtocolAddress) = a.name

    // ---------- identity ----------
    override fun getIdentityKeyPair(): IdentityKeyPair = identity.identityKeyPair
    override fun getLocalRegistrationId(): Int = identity.registrationId

    /** Called ONLY by InviteManager/QR verification flows. */
    fun pinIdentity(address: String, key: IdentityKey, verifiedInPerson: Boolean) {
        val existing = db.getBlob("identities", "address", address, "identity_key")
        require(existing == null || existing.contentEquals(key.serialize())) {
            "Refusing to replace a pinned identity key for $address"
        }
        db.putBlob("identities", "address", address, "identity_key", key.serialize(),
            ContentValues().apply { put("verified", if (verifiedInPerson) 1 else 0) })
    }

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
        // libsignal calls this when a session is built; we only accept the already-pinned key.
        val pinned = getIdentity(address)
            ?: throw SecurityException("Unpinned identity ${address.name}: contact must come from an invite")
        if (pinned != identityKey) throw SecurityException("Identity key changed for ${address.name} — blocked")
        return IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean =
        getIdentity(address)?.let { it == identityKey } ?: false

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? =
        db.getBlob("identities", "address", key(address), "identity_key")?.let { IdentityKey(it, 0) }

    // ---------- one-time prekeys ----------
    override fun loadPreKey(id: Int) = db.getBlob("prekeys", "id", id, "record")?.let { PreKeyRecord(it) }
        ?: throw InvalidKeyIdException("No prekey $id")
    override fun storePreKey(id: Int, record: PreKeyRecord) { db.putBlob("prekeys", "id", id, "record", record.serialize()) }
    override fun containsPreKey(id: Int) = db.getBlob("prekeys", "id", id, "record") != null
    override fun removePreKey(id: Int) { db.delete("prekeys", "id", id) } // one-time: deleted after use

    // ---------- signed prekeys ----------
    override fun loadSignedPreKey(id: Int) = db.getBlob("signed_prekeys", "id", id, "record")?.let { SignedPreKeyRecord(it) }
        ?: throw InvalidKeyIdException("No signed prekey $id")
    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> =
        db.readableDatabase.rawQuery("SELECT record FROM signed_prekeys", null).use { c ->
            buildList { while (c.moveToNext()) add(SignedPreKeyRecord(c.getBlob(0))) }
        }
    override fun storeSignedPreKey(id: Int, record: SignedPreKeyRecord) { db.putBlob("signed_prekeys", "id", id, "record", record.serialize()) }
    override fun containsSignedPreKey(id: Int) = db.getBlob("signed_prekeys", "id", id, "record") != null
    override fun removeSignedPreKey(id: Int) { db.delete("signed_prekeys", "id", id) }

    // ---------- post-quantum (Kyber) prekeys, used by PQXDH ----------
    override fun loadKyberPreKey(id: Int) = db.getBlob("kyber_prekeys", "id", id, "record")?.let { KyberPreKeyRecord(it) }
        ?: throw InvalidKeyIdException("No kyber prekey $id")
    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> =
        db.readableDatabase.rawQuery("SELECT record FROM kyber_prekeys", null).use { c ->
            buildList { while (c.moveToNext()) add(KyberPreKeyRecord(c.getBlob(0))) }
        }
    override fun storeKyberPreKey(id: Int, record: KyberPreKeyRecord) { db.putBlob("kyber_prekeys", "id", id, "record", record.serialize()) }
    override fun containsKyberPreKey(id: Int) = db.getBlob("kyber_prekeys", "id", id, "record") != null
    override fun markKyberPreKeyUsed(id: Int, signedPreKeyId: Int, baseKey: ECPublicKey) {
        db.writableDatabase.execSQL("UPDATE kyber_prekeys SET used = 1 WHERE id = ?", arrayOf(id))
    }

    // ---------- sessions ----------
    override fun loadSession(a: SignalProtocolAddress): SessionRecord =
        db.readableDatabase.rawQuery("SELECT record FROM sessions WHERE address = ? AND device = ?", arrayOf(a.name, a.deviceId.toString()))
            .use { if (it.moveToFirst()) SessionRecord(it.getBlob(0)) else SessionRecord() }
    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
        addresses.map { a -> loadSession(a).also { check(it.hasSenderChain()) { "No session for ${a.name}" } } }
    override fun getSubDeviceSessions(name: String): List<Int> =
        db.readableDatabase.rawQuery("SELECT device FROM sessions WHERE address = ? AND device != 1", arrayOf(name))
            .use { c -> buildList { while (c.moveToNext()) add(c.getInt(0)) } }
    override fun storeSession(a: SignalProtocolAddress, record: SessionRecord) {
        db.writableDatabase.insertWithOnConflict("sessions", null, ContentValues().apply {
            put("address", a.name); put("device", a.deviceId); put("record", record.serialize())
        }, net.zetetic.database.sqlcipher.SQLiteDatabase.CONFLICT_REPLACE)
    }
    override fun containsSession(a: SignalProtocolAddress) = loadSession(a).hasSenderChain()
    override fun deleteSession(a: SignalProtocolAddress) {
        db.writableDatabase.delete("sessions", "address = ? AND device = ?", arrayOf(a.name, a.deviceId.toString()))
    }
    override fun deleteAllSessions(name: String) { db.writableDatabase.delete("sessions", "address = ?", arrayOf(name)) }

    // ---------- group sender keys ----------
    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) {
        db.writableDatabase.insertWithOnConflict("sender_keys", null, ContentValues().apply {
            put("address", sender.name); put("device", sender.deviceId); put("distribution", distributionId.toString()); put("record", record.serialize())
        }, net.zetetic.database.sqlcipher.SQLiteDatabase.CONFLICT_REPLACE)
    }
    override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? =
        db.readableDatabase.rawQuery("SELECT record FROM sender_keys WHERE address = ? AND device = ? AND distribution = ?",
            arrayOf(sender.name, sender.deviceId.toString(), distributionId.toString()))
            .use { if (it.moveToFirst()) SenderKeyRecord(it.getBlob(0)) else null }
}
