package com.cipher.p2p.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Layer 1 — hardware root of trust.
 *
 * A non-exportable AES-256-GCM key lives inside the Android Keystore (StrongBox secure
 * element when the phone has one, otherwise the TEE). Every other secret in the app —
 * the identity key and the database key — is stored only in *wrapped* form, encrypted by
 * this key. Copying the app's files off the phone yields nothing usable.
 */
class KeystoreVault(private val context: Context) {

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun masterKey(): SecretKey {
        (keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        return try {
            generate(strongBox = hasStrongBox())
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)   // Keystore picks the IV; no IV reuse possible
            .setUnlockedDeviceRequired(true)         // unusable while the phone is locked
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    private fun hasStrongBox() =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /** Returns version(1) | iv(12) | ciphertext+tag. [aad] binds the blob to its purpose. */
    fun wrap(plaintext: ByteArray, aad: String): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey())
        cipher.updateAAD(aad.toByteArray())
        val ct = cipher.doFinal(plaintext)
        return byteArrayOf(VERSION) + cipher.iv + ct
    }

    fun unwrap(blob: ByteArray, aad: String): ByteArray {
        require(blob.size > 1 + IV_LEN && blob[0] == VERSION) { "Bad vault blob" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, masterKey(), GCMParameterSpec(128, blob, 1, IV_LEN))
        cipher.updateAAD(aad.toByteArray())
        return cipher.doFinal(blob, 1 + IV_LEN, blob.size - 1 - IV_LEN) // throws on any tampering
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "cipher.vault.master.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LEN = 12
        private const val VERSION: Byte = 1
    }
}
