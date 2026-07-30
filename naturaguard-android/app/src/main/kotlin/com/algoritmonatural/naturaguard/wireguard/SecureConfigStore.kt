package com.algoritmonatural.naturaguard.wireguard

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * A WireGuard .conf file contains a private key — this is exactly the
 * class of secret androidx.security's EncryptedSharedPreferences exists
 * for. Never store this in the plain SharedPreferences the rest of the
 * app uses (see arpmonitor/GatewayMonitor.kt for an example of data that
 * IS fine unencrypted — a MAC address is not a credential).
 */
class SecureConfigStore(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "naturaguard_wireguard_secure",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun save(configText: String) {
        prefs.edit().putString(KEY_CONFIG, configText).apply()
    }

    fun load(): String? = prefs.getString(KEY_CONFIG, null)

    fun clear() {
        prefs.edit().remove(KEY_CONFIG).apply()
    }

    companion object {
        private const val KEY_CONFIG = "wireguard_config_text"
    }
}
