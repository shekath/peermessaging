package com.cipher.p2p.identity

import android.content.Context
import com.cipher.p2p.security.KeystoreVault
import com.cipher.p2p.security.SecretFile
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.util.KeyHelper
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Layer 3 — identity with no phone number, email or account.
 *
 * A user *is* their Curve25519 identity key, generated on the device and wrapped by the
 * hardware vault. The address other peers use is derived from it, so it can't be spoofed:
 * whoever can sign for the key is the user, nobody else.
 */
class IdentityManager(context: Context, vault: KeystoreVault) {

    private val keyFile = SecretFile(context, vault, "identity_v1")
    private val regFile = SecretFile(context, vault, "registration_v1")

    val identityKeyPair: IdentityKeyPair by lazy {
        keyFile.read()?.let { IdentityKeyPair(it) }
            ?: IdentityKeyPair.generate().also { keyFile.write(it.serialize()) }
    }

    val registrationId: Int by lazy {
        regFile.read()?.let { ByteBuffer.wrap(it).int }
            ?: KeyHelper.generateRegistrationId(false).also {
                regFile.write(ByteBuffer.allocate(4).putInt(it).array())
            }
    }

    /** Stable, public, unspoofable address: base32 of SHA-256(identity public key), 26 chars. */
    val address: String by lazy { addressOf(identityKeyPair.publicKey.serialize()) }

    fun exists(): Boolean = keyFile.read() != null

    /** Panic wipe: destroys keys. All local data becomes permanently undecryptable. */
    fun destroy() { keyFile.destroy(); regFile.destroy() }

    companion object {
        fun addressOf(identityPublicKey: ByteArray): String {
            val h = MessageDigest.getInstance("SHA-256").digest(identityPublicKey)
            return Base32.encode(h.copyOf(16)).lowercase()
        }

        /** 60-digit safety number shown on both phones for an optional in-person check. */
        fun safetyNumber(mine: ByteArray, theirs: ByteArray): String {
            val (a, b) = if (compare(mine, theirs) < 0) mine to theirs else theirs to mine
            var digest = a + b
            repeat(5200) { digest = MessageDigest.getInstance("SHA-512").digest(digest + a) } // slow on purpose
            return (0 until 12).joinToString(" ") { i ->
                val chunk = ((digest[i * 5].toLong() and 0xff) shl 32) or
                    ((digest[i * 5 + 1].toLong() and 0xff) shl 24) or ((digest[i * 5 + 2].toLong() and 0xff) shl 16) or
                    ((digest[i * 5 + 3].toLong() and 0xff) shl 8) or (digest[i * 5 + 4].toLong() and 0xff)
                "%05d".format(chunk % 100000)
            }
        }

        private fun compare(x: ByteArray, y: ByteArray): Int {
            for (i in 0 until minOf(x.size, y.size)) { val d = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff); if (d != 0) return d }
            return x.size - y.size
        }
    }
}

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fun encode(data: ByteArray): String {
        val sb = StringBuilder(); var buffer = 0; var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff); bits += 8
            while (bits >= 5) { sb.append(ALPHABET[(buffer shr (bits - 5)) and 31]); bits -= 5 }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.toString()
    }
}
