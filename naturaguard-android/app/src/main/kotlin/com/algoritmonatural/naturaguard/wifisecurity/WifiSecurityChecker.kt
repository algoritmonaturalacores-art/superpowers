package com.algoritmonatural.naturaguard.wifisecurity

import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import com.algoritmonatural.naturaguard.shared.EventLogger
import com.algoritmonatural.naturaguard.shared.Severity
import com.algoritmonatural.naturaguard.shared.SecurityEvent

enum class WifiSecurityLevel { OPEN, WEP, SECURE, UNKNOWN }

data class WifiSecurityResult(
    val ssid: String,
    val level: WifiSecurityLevel,
)

/**
 * Reading Wi-Fi scan results requires a location permission on Android
 * before API 33, or NEARBY_WIFI_DEVICES from API 33 — this class only
 * checks whether that access exists, it never requests it silently.
 * Callers must check hasRequiredPermission() first, same pattern as
 * UsageAuditManager.
 */
class WifiSecurityChecker(private val context: Context) {

    private val eventLogger = EventLogger(context)

    fun hasRequiredPermission(): Boolean {
        val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            android.Manifest.permission.NEARBY_WIFI_DEVICES
        } else {
            android.Manifest.permission.ACCESS_FINE_LOCATION
        }
        return context.checkSelfPermission(permission) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    fun buildGrantAccessIntent(): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = android.net.Uri.fromParts("package", context.packageName, null)
        }

    /**
     * Checks the currently-associated network's advertised capabilities
     * from the last scan. Not a runtime handshake inspection — it reads
     * what the access point itself broadcasts, the same information any
     * Wi-Fi picker UI shows.
     */
    fun checkCurrentNetwork(): WifiSecurityResult? {
        check(hasRequiredPermission()) {
            "Missing permission — call buildGrantAccessIntent() first"
        }

        val wifiManager = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as WifiManager
        val connectionInfo = wifiManager.connectionInfo
        val currentBssid = connectionInfo?.bssid ?: return null
        val currentSsid = connectionInfo.ssid?.trim('"') ?: "desconhecida"

        val scanResult = wifiManager.scanResults.firstOrNull { it.BSSID == currentBssid }
            ?: return WifiSecurityResult(currentSsid, WifiSecurityLevel.UNKNOWN)

        val capabilities = scanResult.capabilities ?: ""
        val level = when {
            capabilities.contains("WEP") -> WifiSecurityLevel.WEP
            capabilities.contains("WPA") -> WifiSecurityLevel.SECURE
            capabilities.contains("EAP") -> WifiSecurityLevel.SECURE
            capabilities.isBlank() || capabilities == "[ESS]" -> WifiSecurityLevel.OPEN
            else -> WifiSecurityLevel.UNKNOWN
        }

        logIfInsecure(currentSsid, level)
        return WifiSecurityResult(currentSsid, level)
    }

    private fun logIfInsecure(ssid: String, level: WifiSecurityLevel) {
        val (severity, message) = when (level) {
            WifiSecurityLevel.OPEN -> Severity.CRITICAL to
                "Ligado a uma rede Wi-Fi aberta, sem palavra-passe: \"$ssid\"."
            WifiSecurityLevel.WEP -> Severity.CRITICAL to
                "Ligado a uma rede Wi-Fi com cifra WEP, obsoleta e quebrável em minutos: \"$ssid\"."
            else -> return
        }
        eventLogger.log(
            SecurityEvent(
                type = "insecure_wifi_network",
                severity = severity,
                message = message,
                source = "wifisecurity",
                extra = mapOf("ssid" to ssid, "level" to level.name),
            )
        )
    }
}
