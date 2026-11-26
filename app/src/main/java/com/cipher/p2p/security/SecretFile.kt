package com.cipher.p2p.security

import android.content.Context
import java.io.File
import java.security.SecureRandom

/** Small helper: a secret that is generated once, wrapped by the vault, and stored as a file. */
class SecretFile(context: Context, private val vault: KeystoreVault, name: String) {
    private val file = File(context.noBackupFilesDir, "$name.bin")
    private val aad = "cipher/secret/$name"

    fun getOrCreate(size: Int = 32): ByteArray {
        if (file.exists()) return vault.unwrap(file.readBytes(), aad)
        val secret = ByteArray(size).also { SecureRandom().nextBytes(it) }
        write(secret)
        return secret
    }

    fun read(): ByteArray? = if (file.exists()) vault.unwrap(file.readBytes(), aad) else null

    fun write(secret: ByteArray) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(vault.wrap(secret, aad))
        check(tmp.renameTo(file)) { "Atomic write failed" }
    }

    fun destroy() { if (file.exists()) { file.writeBytes(ByteArray(file.length().toInt())); file.delete() } }
}

/** Overwrite sensitive arrays as soon as they are no longer needed. */
fun ByteArray.wipe() = fill(0)
