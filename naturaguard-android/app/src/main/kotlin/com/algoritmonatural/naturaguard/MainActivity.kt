package com.algoritmonatural.naturaguard

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.algoritmonatural.naturaguard.arpmonitor.GatewayCheckResult
import com.algoritmonatural.naturaguard.arpmonitor.GatewayMonitor
import com.algoritmonatural.naturaguard.deviceowner.DeviceOwnerReceiver
import com.algoritmonatural.naturaguard.report.ReportActivity
import com.algoritmonatural.naturaguard.rootdetection.RootDetector
import com.algoritmonatural.naturaguard.shared.EventLogger
import com.algoritmonatural.naturaguard.usageaudit.UsageAuditManager
import com.algoritmonatural.naturaguard.vpnmonitor.NetworkMonitorService
import com.algoritmonatural.naturaguard.wifisecurity.WifiSecurityChecker
import com.algoritmonatural.naturaguard.wifisecurity.WifiSecurityLevel
import com.algoritmonatural.naturaguard.wireguard.TunnelConfigActivity

class MainActivity : Activity() {

    private val vpnPermissionRequestCode = 100

    private lateinit var eventLogger: EventLogger
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        eventLogger = EventLogger(applicationContext)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
        }

        statusText = TextView(this).apply {
            text = "NaturaGuard — estado inicial"
        }
        root.addView(statusText)

        root.addView(Button(this).apply {
            text = "Iniciar monitor de rede"
            setOnClickListener { requestVpnPermission() }
        })

        root.addView(Button(this).apply {
            text = "Parar monitor de rede"
            setOnClickListener { stopVpnMonitor() }
        })

        root.addView(Button(this).apply {
            text = "Verificar root"
            setOnClickListener { runRootCheck() }
        })

        root.addView(Button(this).apply {
            text = "Auditoria de uso de apps (24h)"
            setOnClickListener { runUsageAudit() }
        })

        root.addView(Button(this).apply {
            text = "Estado do modo dispositivo dedicado"
            setOnClickListener { checkDeviceOwnerStatus() }
        })

        root.addView(Button(this).apply {
            text = "Verificar segurança do Wi-Fi atual"
            setOnClickListener { runWifiSecurityCheck() }
        })

        root.addView(Button(this).apply {
            text = "Verificar MAC do gateway (ARP)"
            setOnClickListener { runGatewayCheck() }
        })

        root.addView(Button(this).apply {
            text = "Ver relatório de eventos"
            setOnClickListener { startActivity(Intent(this@MainActivity, ReportActivity::class.java)) }
        })

        root.addView(Button(this).apply {
            text = "Configurar VPN segura (WireGuard)"
            setOnClickListener { startActivity(Intent(this@MainActivity, TunnelConfigActivity::class.java)) }
        })

        setContentView(root)
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, vpnPermissionRequestCode)
        } else {
            onActivityResult(vpnPermissionRequestCode, Activity.RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPermissionRequestCode && resultCode == Activity.RESULT_OK) {
            startService(Intent(this, NetworkMonitorService::class.java))
            statusText.text = "Monitor de rede a correr."
        } else if (requestCode == vpnPermissionRequestCode) {
            statusText.text = "Permissão de VPN recusada — monitor de rede inativo."
        }
    }

    private fun stopVpnMonitor() {
        val intent = Intent(this, NetworkMonitorService::class.java).apply {
            action = NetworkMonitorService.ACTION_STOP
        }
        startService(intent)
        statusText.text = "Monitor de rede parado."
    }

    private fun runRootCheck() {
        val suspected = RootDetector(this).checkAndLog()
        statusText.text = if (suspected) {
            "Indícios de root detetados — ver relatório."
        } else {
            "Sem indícios de root."
        }
    }

    private fun runUsageAudit() {
        val manager = UsageAuditManager(this)
        if (!manager.hasUsageAccess()) {
            Toast.makeText(
                this,
                "Conceda acesso a 'Dados de utilização' nas Definições para continuar.",
                Toast.LENGTH_LONG,
            ).show()
            startActivity(manager.buildGrantAccessIntent())
            return
        }
        val summaries = manager.auditLast24Hours()
        statusText.text = "Auditoria concluída: ${summaries.size} apps com atividade nas últimas 24h."
    }

    private fun checkDeviceOwnerStatus() {
        val isOwner = DeviceOwnerReceiver.isDeviceOwner(this)
        statusText.text = if (isOwner) {
            "Este dispositivo está em modo dedicado (Device Owner)."
        } else {
            "Modo dedicado não ativo. Funcionalidades de auditoria de outras apps " +
                "permanecem bloqueadas até este modo ser aprovisionado com consentimento explícito."
        }
    }

    private fun runWifiSecurityCheck() {
        val checker = WifiSecurityChecker(this)
        if (!checker.hasRequiredPermission()) {
            Toast.makeText(
                this,
                "Conceda a permissão de Wi-Fi/localização pedida nas Definições da app para continuar.",
                Toast.LENGTH_LONG,
            ).show()
            startActivity(checker.buildGrantAccessIntent())
            return
        }
        val result = checker.checkCurrentNetwork()
        statusText.text = if (result == null) {
            "Não foi possível determinar a segurança da rede atual."
        } else {
            when (result.level) {
                WifiSecurityLevel.OPEN -> "Rede Wi-Fi \"${result.ssid}\" está ABERTA — sem palavra-passe."
                WifiSecurityLevel.WEP -> "Rede Wi-Fi \"${result.ssid}\" usa WEP — cifra obsoleta e quebrável."
                WifiSecurityLevel.SECURE -> "Rede Wi-Fi \"${result.ssid}\" está protegida (WPA/WPA2/WPA3)."
                WifiSecurityLevel.UNKNOWN -> "Segurança da rede \"${result.ssid}\" desconhecida."
            }
        }
    }

    private fun runGatewayCheck() {
        when (GatewayMonitor(this).checkGatewayMac()) {
            GatewayCheckResult.UNCHANGED -> statusText.text = "MAC do gateway igual ao registado — sem alterações."
            GatewayCheckResult.CHANGED -> statusText.text = "ALERTA: MAC do gateway mudou — ver relatório."
            GatewayCheckResult.FIRST_SEEN -> statusText.text = "MAC do gateway registado pela primeira vez."
            GatewayCheckResult.DEGRADED -> statusText.text =
                "Não foi possível ler a tabela ARP neste dispositivo (normal sem root em Android 10+)."
        }
    }
}
