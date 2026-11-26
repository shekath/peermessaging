plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.cipher.p2p"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.cipher.p2p"
        minSdk = 28            // StrongBox + modern Keystore + TLS 1.3
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true          // R8 shrink + obfuscate
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug { applicationIdSuffix = ".debug" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

dependencies {
    // Audited crypto only — never hand-rolled primitives.
    implementation("org.signal:libsignal-android:0.64.1")       // X3DH/PQXDH + Double Ratchet (AGPL-3.0)
    implementation("com.google.crypto.tink:tink-android:1.15.0") // HKDF / AEAD helpers
    implementation("net.zetetic:sqlcipher-android:4.6.1")        // encrypted SQLite
    implementation("androidx.sqlite:sqlite-ktx:2.4.0")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-cbor:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.zxing:core:3.5.3")                // QR encode/decode
    implementation("com.github.mik3y:usb-serial-for-android:3.8.1") // LoRa radio over USB-C

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-ktx:1.9.3")

    testImplementation("junit:junit:4.13.2")
}
