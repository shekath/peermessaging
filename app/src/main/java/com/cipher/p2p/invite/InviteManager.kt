package com.cipher.p2p.invite

import android.content.ContentValues
import android.util.Base64
import com.cipher.p2p.identity.IdentityManager
import com.cipher.p2p.storage.SecureDatabase
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import org.signal.libsignal.protocol.IdentityKey
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Layer 4 — contact exchange with invite links and QR codes only. No phone numbers.
 *
 * An invite carries the inviter's public identity key, where to reach them, a single-use
 * 256-bit secret and an expiry, all signed by the identity key. Properties:
 *  - Forgery-proof: the signature is checked against the key inside the invite, and the
 *    resulting contact is pinned to exactly that key (no trust-on-first-use from strangers).
 *  - Single use: the inviter stores only SHA-256(secret) and burns it on first redemption,
 *    so a leaked or screenshotted link can't be reused.
 *  - Short-lived: default 24 h.
 *  - Private: the link puts the payload after '#', which browsers and link previewers never send.
 */
@OptIn(ExperimentalSerializationApi::class)
class InviteManager(
    private val identity: IdentityManager,
    private val db: SecureDatabase,
) {
    @Serializable
    data class InvitePayload(
        val v: Int = 1,
        val identityKey: ByteArray,     // 33-byte Curve25519 public key
        val reach: List<String>,        // transport hints, e.g. "p2p:/dns4/…", "wifi:cipher-7f3a", "onion:…"
        val secret: ByteArray,          // 32 random bytes, single use
        val expiresAt: Long,            // epoch seconds
        val name: String? = null,       // optional display name (≤ 32 chars), never required
        val sig: ByteArray = ByteArray(0),
    )

    @Serializable
    data class RedeemRequest(
        val inviteeIdentityKey: ByteArray,
        val inviteeBundle: ByteArray,   // serialized prekey bundle (see SessionManager.exportBundle)
        val nonce: ByteArray,           // 16 random bytes
        val proof: ByteArray,           // HMAC-SHA256(secret, transcript)
    )

    private val rng = SecureRandom()

    fun create(reach: List<String>, name: String? = null, ttlSeconds: Long = 24 * 3600): Pair<String, InvitePayload> {
        require(name == null || name.length <= 32) { "Name too long" }
        val secret = ByteArray(32).also(rng::nextBytes)
        val unsigned = InvitePayload(
            identityKey = identity.identityKeyPair.publicKey.serialize(),
            reach = reach, secret = secret,
            expiresAt = System.currentTimeMillis() / 1000 + ttlSeconds, name = name,
        )
        val sig = identity.identityKeyPair.privateKey.calculateSignature(signedBytes(unsigned))
        val payload = unsigned.copy(sig = sig)

        // Stored inside the SQLCipher database (encrypted at rest, key in hardware vault).
        db.writableDatabase.insertOrThrow("invites", null, ContentValues().apply {
            put("secret", secret); put("expires_at", payload.expiresAt); put("used", 0)
        })

        val encoded = Base64.encodeToString(Cbor.encodeToByteArray(payload),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        return "cipher://invite#$encoded" to payload
    }

    /** Invitee side: parse and verify a scanned/opened invite. Throws on anything wrong. */
    fun parseAndVerify(link: String): InvitePayload {
        val frag = link.substringAfter("cipher://invite#", "")
        require(frag.isNotEmpty() && frag.length < 2048) { "Not a Cipher invite" }
        val p = Cbor.decodeFromByteArray<InvitePayload>(Base64.decode(frag, Base64.URL_SAFE or Base64.NO_PADDING))
        require(p.v == 1) { "Unsupported invite version" }
        require(p.secret.size == 32 && p.identityKey.size == 33) { "Malformed invite" }
        require(p.expiresAt > System.currentTimeMillis() / 1000) { "Invite expired" }
        require(p.reach.size in 1..8 && p.reach.all { it.length < 256 }) { "Bad reach hints" }
        val key = IdentityKey(p.identityKey, 0)
        require(key.publicKey.verifySignature(signedBytes(p.copy(sig = ByteArray(0))), p.sig)) { "Invite signature invalid" }
        require(!p.identityKey.contentEquals(identity.identityKeyPair.publicKey.serialize())) { "That's your own invite" }
        return p
    }

    /** Invitee side: build the request that proves we hold the secret. */
    fun buildRedeem(invite: InvitePayload, myBundle: ByteArray): RedeemRequest {
        val nonce = ByteArray(16).also(rng::nextBytes)
        val me = identity.identityKeyPair.publicKey.serialize()
        return RedeemRequest(me, myBundle, nonce, hmac(invite.secret, transcript(invite.identityKey, me, myBundle, nonce)))
    }

    /**
     * Inviter side: verify a redemption against our stored, unused secrets. Returns the
     * invitee's identity key to pin, or null. Burns the secret atomically on success.
     */
    fun verifyRedeem(req: RedeemRequest): IdentityKey? {
        require(req.inviteeIdentityKey.size == 33 && req.nonce.size == 16) { "Malformed redeem" }
        val me = identity.identityKeyPair.publicKey.serialize()
        val t = transcript(me, req.inviteeIdentityKey, req.inviteeBundle, req.nonce)
        val now = System.currentTimeMillis() / 1000
        val w = db.writableDatabase
        w.delete("invites", "expires_at <= ? OR used = 1", arrayOf(now.toString())) // purge burned/expired
        val candidates = w.rawQuery("SELECT secret FROM invites WHERE used = 0 AND expires_at > ?", arrayOf(now.toString()))
            .use { c -> buildList { while (c.moveToNext()) add(c.getBlob(0)) } }
        for (secret in candidates) {
            if (!MessageDigest.isEqual(hmac(secret, t), req.proof)) continue   // constant-time compare
            w.beginTransaction()
            try {
                val burned = w.compileStatement(
                    "UPDATE invites SET used = 1 WHERE secret = ? AND used = 0 AND expires_at > ?"
                ).apply { bindBlob(1, secret); bindLong(2, now) }.executeUpdateDelete()
                w.setTransactionSuccessful()
                return if (burned == 1) IdentityKey(req.inviteeIdentityKey, 0) else null
            } finally { w.endTransaction() }
        }
        return null
    }

    fun qrMatrix(link: String, size: Int = 720) = QRCodeWriter().encode(
        link, BarcodeFormat.QR_CODE, size, size,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2)
    )

    private fun signedBytes(p: InvitePayload) = "cipher-invite-v1".toByteArray() + Cbor.encodeToByteArray(p.copy(sig = ByteArray(0)))
    private fun transcript(inviter: ByteArray, invitee: ByteArray, bundle: ByteArray, nonce: ByteArray) =
        "cipher-redeem-v1".toByteArray() + inviter + invitee + sha256(bundle) + nonce
    private fun hmac(key: ByteArray, data: ByteArray) =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
}
