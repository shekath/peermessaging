package com.cipher.p2p.crypto

import com.cipher.p2p.identity.IdentityManager
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import java.security.SecureRandom

/**
 * Layer 6 — end-to-end encryption with Signal's protocol (PQXDH + Double Ratchet).
 *
 *  - Forward secrecy: every message uses a fresh key; stealing today's keys can't read yesterday's.
 *  - Post-compromise security: the ratchet heals after a key leak once both sides exchange messages.
 *  - Post-quantum: Kyber-1024 is mixed into the first handshake ("harvest now, decrypt later" defence).
 *  - Authentication: libsignal verifies the signed prekeys against the pinned identity key.
 */
@OptIn(ExperimentalSerializationApi::class)
class SessionManager(
    private val identity: IdentityManager,
    private val store: PinnedProtocolStore,
) {
    @Serializable
    data class Bundle(
        val registrationId: Int, val identityKey: ByteArray,
        val preKeyId: Int, val preKey: ByteArray,
        val signedPreKeyId: Int, val signedPreKey: ByteArray, val signedPreKeySig: ByteArray,
        val kyberPreKeyId: Int, val kyberPreKey: ByteArray, val kyberPreKeySig: ByteArray,
    )

    private val rng = SecureRandom()
    private fun newId() = (rng.nextInt(0xFFFFFF) + 1)

    /** Fresh one-time keys for one contact; sent during invite redemption. */
    fun exportBundle(): ByteArray {
        val idKp = identity.identityKeyPair
        val now = System.currentTimeMillis()

        val preId = newId()
        val preKp = ECKeyPair.generate()
        store.storePreKey(preId, PreKeyRecord(preId, preKp))

        val spId = newId()
        val spKp = ECKeyPair.generate()
        val spSig = idKp.privateKey.calculateSignature(spKp.publicKey.serialize())
        store.storeSignedPreKey(spId, SignedPreKeyRecord(spId, now, spKp, spSig))

        val kyId = newId()
        val kyKp = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kySig = idKp.privateKey.calculateSignature(kyKp.publicKey.serialize())
        store.storeKyberPreKey(kyId, KyberPreKeyRecord(kyId, now, kyKp, kySig))

        return Cbor.encodeToByteArray(Bundle(
            identity.registrationId, idKp.publicKey.serialize(),
            preId, preKp.publicKey.serialize(),
            spId, spKp.publicKey.serialize(), spSig,
            kyId, kyKp.publicKey.serialize(), kySig,
        ))
    }

    /** Build an outgoing session from a peer's bundle. The identity must already be pinned. */
    fun startSession(peerAddress: String, bundleBytes: ByteArray) {
        val b = Cbor.decodeFromByteArray<Bundle>(bundleBytes)
        val idKey = IdentityKey(b.identityKey, 0)
        require(IdentityManager.addressOf(b.identityKey) == peerAddress) { "Bundle doesn't belong to $peerAddress" }
        val bundle = PreKeyBundle(
            b.registrationId, DEVICE,
            b.preKeyId, ECPublicKey(b.preKey, 0),
            b.signedPreKeyId, ECPublicKey(b.signedPreKey, 0), b.signedPreKeySig,
            idKey,
            b.kyberPreKeyId, KEMPublicKey(b.kyberPreKey), b.kyberPreKeySig,
        )
        SessionBuilder(store, addr(peerAddress)).process(bundle) // verifies signatures + pinned identity
    }

    fun encrypt(peerAddress: String, plaintext: ByteArray): Pair<Int, ByteArray> {
        val msg = SessionCipher(store, addr(peerAddress)).encrypt(Padding.pad(plaintext))
        return msg.type to msg.serialize()
    }

    fun decrypt(peerAddress: String, type: Int, body: ByteArray): ByteArray {
        val cipher = SessionCipher(store, addr(peerAddress))
        val padded = when (type) {
            CiphertextMessage.PREKEY_TYPE -> cipher.decrypt(PreKeySignalMessage(body))
            CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(SignalMessage(body))
            else -> throw SecurityException("Unknown message type $type")
        }
        return Padding.unpad(padded)
    }

    private fun addr(a: String) = SignalProtocolAddress(a, DEVICE)
    companion object { const val DEVICE = 1 }
}

/**
 * Hides message length (a metadata leak) by padding to fixed buckets before encryption.
 * Format: plaintext | 0x80 | 0x00…  (ISO/IEC 7816-4).
 */
object Padding {
    private val BUCKETS = intArrayOf(160, 512, 1024, 4096, 16384, 65536)
    fun pad(p: ByteArray): ByteArray {
        val target = BUCKETS.firstOrNull { it > p.size } ?: ((p.size / 65536) + 1) * 65536
        return ByteArray(target).also { p.copyInto(it); it[p.size] = 0x80.toByte() }
    }
    fun unpad(p: ByteArray): ByteArray {
        val end = p.indexOfLast { it != 0.toByte() }
        require(end >= 0 && p[end] == 0x80.toByte()) { "Bad padding" }
        return p.copyOf(end)
    }
}
