package com.algoritmonatural.naturaguard.arpmonitor

import android.content.Context
import android.net.wifi.WifiManager
import com.algoritmonatural.naturaguard.shared.EventLogger
import com.algoritmonatural.naturaguard.shared.Severity
import com.algoritmonatural.naturaguard.shared.SecurityEvent
import java.io.File

enum class GatewayCheckResult { UNCHANGED, CHANGED, FIRST_SEEN, DEGRADED }

/**
 * Mirrors netguard/netguard.py's gateway_mac_changed detection: if the
 * router's MAC address changes without you having replaced the router,
 * that's the signature of ARP spoofing / a man-in-the-middle on the LAN.
 *
 * Same honest limitation netguard/README.md documents for Android: from
 * Android 10 onward, apps without root cannot read /proc/net/arp. When
 * that happens this returns DEGRADED rather than pretending the check
 * succeeded — see netguard's own `degraded_scan` event for the same
 * pattern on the Termux side.
 */
class GatewayMonitor(private val context: Context) {

    private val eventLogger = EventLogger(context)
    private val prefs = context.getSharedPreferences("naturaguard_gateway", Context.MODE_PRIVATE)

    fun checkGatewayMac(): GatewayCheckResult {
        val gatewayIp = currentGatewayIp() ?: return GatewayCheckResult.DEGRADED
        val currentMac = readMacFromArpTable(gatewayIp)

        if (currentMac == null) {
            eventLogger.log(
                SecurityEvent(
                    type = "degraded_scan",
                    severity = Severity.WARNING,
                    message = "Não foi possível ler a tabela ARP (normal em Android 10+ sem root) — " +
                        "deteção de mudança de gateway inativa nesta verificação.",
                    source = "arpmonitor",
                )
            )
            return GatewayCheckResult.DEGRADED
        }

        val knownMac = prefs.getString(KEY_GATEWAY_MAC, null)
        if (knownMac == null) {
            prefs.edit().putString(KEY_GATEWAY_MAC, currentMac).apply()
            eventLogger.log(
                SecurityEvent(
                    type = "gateway_mac_learned",
                    severity = Severity.INFO,
                    message = "MAC do gateway registado pela primeira vez: $currentMac.",
                    source = "arpmonitor",
                )
            )
            return GatewayCheckResult.FIRST_SEEN
        }

        if (!knownMac.equals(currentMac, ignoreCase = true)) {
            eventLogger.log(
                SecurityEvent(
                    type = "gateway_mac_changed",
                    severity = Severity.CRITICAL,
                    message = "O MAC do gateway mudou de $knownMac para $currentMac — possível ARP spoofing.",
                    source = "arpmonitor",
                    extra = mapOf("previous_mac" to knownMac, "current_mac" to currentMac),
                )
            )
            prefs.edit().putString(KEY_GATEWAY_MAC, currentMac).apply()
            return GatewayCheckResult.CHANGED
        }

        return GatewayCheckResult.UNCHANGED
    }

    private fun currentGatewayIp(): String? {
        val wifiManager = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as WifiManager
        @Suppress("DEPRECATION")
        val gatewayInt = wifiManager.dhcpInfo?.gateway ?: return null
        if (gatewayInt == 0) return null
        return listOf(
            gatewayInt and 0xFF,
            (gatewayInt shr 8) and 0xFF,
            (gatewayInt shr 16) and 0xFF,
            (gatewayInt shr 24) and 0xFF,
        ).joinToString(".")
    }

    private fun readMacFromArpTable(gatewayIp: String): String? {
        val arpFile = File("/proc/net/arp")
        if (!arpFile.canRead()) return null

        return try {
            arpFile.readLines()
                .drop(1) // header line
                .map { it.trim().split(Regex("\\s+")) }
                .firstOrNull { it.size >= 4 && it[0] == gatewayIp }
                ?.get(3)
                ?.takeIf { it != "00:00:00:00:00:00" }
        } catch (e: Exception) {
            null
        }
    }

    companion object {
        private const val KEY_GATEWAY_MAC = "gateway_mac"
    }
}
