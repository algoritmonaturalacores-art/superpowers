package com.algoritmonatural.naturaguard.wireguard

import com.wireguard.android.backend.Tunnel

/**
 * Minimal Tunnel implementation required by the official WireGuard Android
 * backend (com.wireguard.android:tunnel). All the actual cryptography and
 * packet handling lives inside that library's GoBackend — this class only
 * identifies the tunnel and reacts to state changes for UI purposes.
 */
class NaturaGuardTunnel(
    private val tunnelName: String,
    private val onStateChanged: (Tunnel.State) -> Unit = {},
) : Tunnel {

    override fun getName(): String = tunnelName

    override fun onStateChange(newState: Tunnel.State) {
        onStateChanged(newState)
    }
}
