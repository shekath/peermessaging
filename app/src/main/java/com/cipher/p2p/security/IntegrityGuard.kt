package com.cipher.p2p.security

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.view.WindowManager
import java.io.File
import java.security.MessageDigest

/**
 * Layer 8 — device hygiene. These checks raise the cost of attacks on a compromised phone;
 * they are NOT the security boundary (a rooted attacker can bypass any client check).
 * The real guarantees come from the crypto layers above.
 */
object IntegrityGuard {

    /** SHA-256 of your release signing certificate. Set at build time. */
    private const val EXPECTED_CERT_SHA256 = "REPLACE_WITH_RELEASE_CERT_SHA256_HEX"

    data class Report(val debuggerAttached: Boolean, val signatureMismatch: Boolean, val rootIndicators: Boolean, val emulator: Boolean) {
        val compromised get() = debuggerAttached || signatureMismatch
    }

    fun check(context: Context): Report = Report(
        debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger(),
        signatureMismatch = !signatureMatches(context),
        rootIndicators = listOf("/system/xbin/su", "/system/bin/su", "/sbin/su", "/data/adb/magisk").any { File(it).exists() },
        emulator = Build.FINGERPRINT.contains("generic") || Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu"),
    )

    private fun signatureMatches(context: Context): Boolean {
        if (EXPECTED_CERT_SHA256.startsWith("REPLACE")) return true // not configured (debug builds)
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners ?: return false
        return signers.any { s ->
            MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) } == EXPECTED_CERT_SHA256
        }
    }

    /** Blocks screenshots, screen recording and the recent-apps thumbnail. */
    fun secureWindow(activity: Activity) {
        activity.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) activity.setRecentsScreenshotEnabled(false)
    }
}
