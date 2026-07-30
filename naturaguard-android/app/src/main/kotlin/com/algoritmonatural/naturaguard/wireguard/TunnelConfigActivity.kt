package com.algoritmonatural.naturaguard.wireguard

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

/**
 * Import screen for a WireGuard .conf file — paste the text a self-hosted
 * server or a commercial VPN provider gave you. This screen cannot create
 * a server for you; it only connects to one you already have.
 */
class TunnelConfigActivity : Activity() {

    private lateinit var manager: SecureTunnelManager
    private lateinit var statusText: TextView
    private lateinit var configInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        manager = SecureTunnelManager(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
        }

        root.addView(TextView(this).apply {
            text = "Cole aqui o conteúdo do ficheiro .conf do WireGuard " +
                "(do seu servidor próprio ou do fornecedor VPN). " +
                "Precisa de já ter um servidor WireGuard — este ecrã só liga a um que já exista."
        })

        configInput = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            minLines = 8
            if (manager.hasStoredConfig()) {
                hint = "Configuração já guardada — cole um novo .conf para substituir."
            }
        }
        root.addView(configInput)

        statusText = TextView(this).apply {
            text = if (manager.isConnected()) "Estado: ligado" else "Estado: desligado"
        }
        root.addView(statusText)

        root.addView(Button(this).apply {
            text = "Guardar configuração"
            setOnClickListener { saveConfig() }
        })

        root.addView(Button(this).apply {
            text = "Ligar túnel seguro"
            setOnClickListener { connect() }
        })

        root.addView(Button(this).apply {
            text = "Desligar túnel"
            setOnClickListener { disconnect() }
        })

        setContentView(root)
    }

    private fun saveConfig() {
        val text = configInput.text.toString()
        if (text.isBlank()) {
            Toast.makeText(this, "Cole primeiro o conteúdo do .conf", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            manager.saveConfig(text)
            Toast.makeText(this, "Configuração guardada de forma cifrada.", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Configuração inválida: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun connect() {
        try {
            manager.connect { state ->
                runOnUiThread { statusText.text = "Estado: $state" }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Não foi possível ligar: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun disconnect() {
        manager.disconnect()
        statusText.text = "Estado: desligado"
    }
}
