package com.algoritmonatural.naturaguard.wireguard

import android.content.Context
import com.algoritmonatural.naturaguard.shared.EventLogger
import com.algoritmonatural.naturaguard.shared.Severity
import com.algoritmonatural.naturaguard.shared.SecurityEvent
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.BufferedReader
import java.io.StringReader

/**
 * Thin wrapper around the official WireGuard GoBackend. Deliberately does
 * NOT implement any tunneling/crypto itself — that would mean re-deriving
 * a security protocol from scratch, which is exactly the kind of mistake
 * that turns a "secure VPN" into a false sense of security. This class
 * only stores/loads a user-supplied config and starts or stops the
 * official backend with it.
 *
 * Requires a WireGuard server the user controls or trusts (self-hosted or
 * commercial) — this class cannot create that server, only connect to one.
 */
class SecureTunnelManager(context: Context) {

    private val appContext = context.applicationContext
    private val backend = GoBackend(appContext)
    private val configStore = SecureConfigStore(appContext)
    private val eventLogger = EventLogger(appContext)

    private var tunnel: NaturaGuardTunnel? = null

    fun hasStoredConfig(): Boolean = configStore.load() != null

    fun saveConfig(configText: String) {
        // Parse before storing so an invalid paste never gets treated as
        // a real config later.
        Config.parse(BufferedReader(StringReader(configText)))
        configStore.save(configText)
    }

    fun clearConfig() {
        configStore.clear()
    }

    fun isConnected(): Boolean =
        tunnel?.let { backend.getState(it) } == Tunnel.State.UP

    fun connect(onStateChanged: (Tunnel.State) -> Unit) {
        val configText = configStore.load()
            ?: error("Nenhuma configuração WireGuard guardada — importe uma primeiro")

        val config = Config.parse(BufferedReader(StringReader(configText)))
        val activeTunnel = NaturaGuardTunnel(TUNNEL_NAME, onStateChanged)
        tunnel = activeTunnel

        backend.setState(activeTunnel, Tunnel.State.UP, config)

        eventLogger.log(
            SecurityEvent(
                type = "secure_tunnel_connected",
                severity = Severity.INFO,
                message = "Túnel WireGuard ligado — tráfego a sair cifrado para o servidor configurado.",
                source = "wireguard",
            )
        )
    }

    fun disconnect() {
        val activeTunnel = tunnel ?: return
        backend.setState(activeTunnel, Tunnel.State.DOWN, null)
        eventLogger.log(
            SecurityEvent(
                type = "secure_tunnel_disconnected",
                severity = Severity.INFO,
                message = "Túnel WireGuard desligado.",
                source = "wireguard",
            )
        )
    }

    companion object {
        private const val TUNNEL_NAME = "naturaguard"
    }
}
