package com.cipher.p2p.ui

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.util.Base64
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.TextView
import androidx.activity.ComponentActivity
import com.cipher.p2p.CipherApp
import com.cipher.p2p.identity.IdentityManager
import com.cipher.p2p.security.IntegrityGuard
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Hardened WebView shell for the UI (from the whiteboard prototype) + a narrow native bridge.
 * All keys and crypto stay in Kotlin; the page only ever gets public data back.
 */
class MainActivity : ComponentActivity() {
    private val app get() = application as CipherApp
    private lateinit var web: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        IntegrityGuard.secureWindow(this)

        if (IntegrityGuard.check(this).compromised) {
            setContentView(TextView(this).apply { text = "Cipher can't run on a tampered app or with a debugger attached." })
            return
        }

        WebView.setWebContentsDebuggingEnabled(false)
        web = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#0b1220"))
            settings.javaScriptEnabled = true
            settings.allowFileAccess = false          // assets still load; nothing else on disk
            settings.allowContentAccess = false
            settings.domStorageEnabled = false
            settings.databaseEnabled = false
            settings.setGeolocationEnabled(false)
            settings.saveFormData = false
            settings.blockNetworkLoads = true         // UI is fully local; no remote content, ever
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest) = true // no navigation
            }
            addJavascriptInterface(Bridge(), "Cipher")
            loadUrl("file:///android_asset/ui.html")
        }
        setContentView(web)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); handleIntent(intent) }

    private fun handleIntent(intent: Intent?) {
        val link = intent?.dataString ?: return
        if (!link.startsWith("cipher://invite#")) return
        val res = Bridge().acceptInvite(link)
        web.post { web.evaluateJavascript("S.tab='contacts';S.chats=[];draw();", null) }
        android.widget.Toast.makeText(this,
            if (JSONObject(res).optBoolean("ok")) "Contact added — key pinned" else "Invalid or expired invite",
            android.widget.Toast.LENGTH_LONG).show()
        setIntent(Intent())
    }

    inner class Bridge {
        @JavascriptInterface fun hasIdentity(): Boolean = app.identity.exists()

        @JavascriptInterface fun createIdentity(name: String) {
            app.identity.identityKeyPair // generates + wraps in hardware vault
            app.db.putBlob("kv", "k", "display_name", "v", name.take(32).toByteArray())
        }

        @JavascriptInterface fun address(): String = app.identity.address

        private fun myName() = app.db.getBlob("kv", "k", "display_name", "v")?.let { String(it) }?.ifBlank { null }

        @JavascriptInterface fun createInvite(): String {
            val (link, _) = app.invites.create(reach = listOf("p2p:${app.identity.address}"), name = myName())
            return JSONObject().put("link", link).put("qr", qrDataUri(link)).toString()
        }

        @JavascriptInterface fun acceptInvite(link: String): String = try {
            val (invite, _) = app.acceptInvite(link)   // verifies signature + expiry, pins identity
            val addr = IdentityManager.addressOf(invite.identityKey)
            val name = invite.name ?: "Contact ${addr.take(6)}"
            app.db.writableDatabase.insertWithOnConflict("contacts", null, ContentValues().apply {
                put("address", addr); put("name", name); put("added_at", System.currentTimeMillis())
            }, net.zetetic.database.sqlcipher.SQLiteDatabase.CONFLICT_REPLACE)
            val safety = IdentityManager.safetyNumber(app.identity.identityKeyPair.publicKey.serialize(), invite.identityKey)
            JSONObject().put("ok", true).put("name", name).put("safety", safety).toString()
        } catch (e: Exception) {
            JSONObject().put("ok", false).toString()     // never leak parser details to the page
        }

        @JavascriptInterface fun contacts(): String {
            val arr = JSONArray()
            app.db.readableDatabase.rawQuery("SELECT address, name FROM contacts ORDER BY added_at DESC", null).use { c ->
                while (c.moveToNext()) arr.put(JSONObject().put("address", c.getString(0)).put("name", c.getString(1)))
            }
            return arr.toString()
        }

        @JavascriptInterface fun share(link: String) {
            if (!link.startsWith("cipher://invite#")) return
            runOnUiThread {
                startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"; putExtra(Intent.EXTRA_TEXT, "Add me on Cipher (expires in 24 h, works once):\n$link")
                }, "Share invite"))
            }
        }

        @JavascriptInterface fun status(): String {
            val strongBox = packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            val r = IntegrityGuard.check(this@MainActivity)
            return JSONObject()
                .put("Key storage", if (strongBox) "StrongBox secure element" else "Hardware TEE")
                .put("Database", "SQLCipher AES-256")
                .put("Encryption", "Signal PQXDH + Double Ratchet")
                .put("Trust model", "Pinned keys only (no TOFU)")
                .put("Screenshots", "Blocked")
                .put("Root indicators", if (r.rootIndicators) "Detected ⚠" else "None found")
                .toString()
        }

        @JavascriptInterface fun panicWipe() {
            app.identity.destroy()
            File(noBackupFilesDir, "db_key.bin").let { if (it.exists()) { it.writeBytes(ByteArray(it.length().toInt())); it.delete() } }
            app.db.close()
            deleteDatabase("cipher.db")
            runOnUiThread { finishAffinity(); Runtime.getRuntime().exit(0) }
        }
    }

    private fun qrDataUri(text: String): String {
        val matrix = app.invites.qrMatrix(text, 600)
        val bmp = Bitmap.createBitmap(matrix.width, matrix.height, Bitmap.Config.RGB_565)
        for (x in 0 until matrix.width) for (y in 0 until matrix.height)
            bmp.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
        val out = ByteArrayOutputStream().also { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
        return "data:image/png;base64," + Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
    }
}
