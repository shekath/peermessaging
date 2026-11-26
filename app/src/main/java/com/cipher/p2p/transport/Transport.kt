package com.cipher.p2p.transport

import com.cipher.p2p.storage.SecureDatabase
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.merge
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import java.security.MessageDigest

/**
 * Layer 7 — transports only ever carry sealed envelopes.
 *
 * Every link (internet P2P, Wi-Fi Direct, same-LAN, LoRa, satellite) sees just
 * [Envelope]: who it's for and an opaque Signal ciphertext. Transports are untrusted by
 * design; a malicious relay or radio can drop or delay messages but can't read or forge them.
 */
@Serializable
data class Envelope(
    val v: Int = 1,
    val to: String,          // recipient address (hash of their identity key)
    val from: String,        // sender address; authenticated by the Signal session, not by this field
    val type: Int,           // Signal message type
    val body: ByteArray,     // ciphertext
    val ts: Long,            // sender clock, seconds — used for replay window only
)

enum class LinkKind(val priority: Int, val maxPayload: Int, val allowsMedia: Boolean) {
    INTERNET(0, 64 * 1024 * 1024, true),
    WIFI_DIRECT(1, 64 * 1024 * 1024, true),
    LAN(1, 64 * 1024 * 1024, true),
    BLE_MESH(2, 4 * 1024, false),
    LORA(3, 600, false),          // ~3 radio packets
    SATELLITE(4, 300, false),
}

interface Transport {
    val kind: LinkKind
    fun isAvailableFor(address: String): Boolean
    suspend fun send(address: String, frame: ByteArray): Boolean
    val incoming: Flow<ByteArray>
}

@OptIn(ExperimentalSerializationApi::class)
class TransportRouter(private val transports: List<Transport>, private val db: SecureDatabase) {

    /** Fastest available link that can carry this payload. Media never goes over LoRa/satellite. */
    suspend fun send(env: Envelope, isMedia: Boolean): LinkKind? {
        val frame = Cbor.encodeToByteArray(env)
        for (t in transports.sortedBy { it.kind.priority }) {
            if (!t.isAvailableFor(env.to)) continue
            if (frame.size > t.kind.maxPayload || (isMedia && !t.kind.allowsMedia)) continue
            if (t.send(env.to, frame)) return t.kind
        }
        return null // caller puts it in the encrypted outbox and retries with backoff
    }

    val incoming: Flow<ByteArray> = transports.map { it.incoming }.merge()

    /**
     * Strict parsing + replay protection before anything reaches the crypto layer.
     * (libsignal also rejects duplicate ratchet messages; this stops cheap floods early.)
     */
    fun accept(frame: ByteArray, myAddress: String): Envelope? {
        if (frame.size > 70 * 1024 * 1024) return null
        val env = runCatching { Cbor.decodeFromByteArray<Envelope>(frame) }.getOrNull() ?: return null
        if (env.v != 1 || env.to != myAddress || env.from.length != 26) return null
        val now = System.currentTimeMillis() / 1000
        if (env.ts !in (now - 7 * 86400)..(now + 300)) return null    // 7-day store-and-forward window
        val h = MessageDigest.getInstance("SHA-256").digest(frame)
        val w = db.writableDatabase
        w.delete("seen_envelopes", "ts < ?", arrayOf((now - 8 * 86400).toString()))
        val fresh = runCatching {
            w.compileStatement("INSERT INTO seen_envelopes(hash, ts) VALUES(?, ?)")
                .apply { bindBlob(1, h); bindLong(2, now) }.executeInsert()
        }.isSuccess
        return if (fresh) env else null
    }
}
