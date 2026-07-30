plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.algoritmonatural.naturaguard"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.algoritmonatural.naturaguard"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets["main"].kotlin.srcDirs("src/main/kotlin")
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")

    // Official WireGuard client for Android — do not replace with a
    // hand-rolled tunnel implementation. https://git.zx2c4.com/wireguard-android/
    implementation("com.wireguard.android:tunnel:1.0.20230706")

    // EncryptedSharedPreferences, used to store the WireGuard config
    // (which contains a private key) instead of plaintext prefs.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}
