package com.algoritmonatural.naturaguard.report

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.algoritmonatural.naturaguard.shared.EventLogger
import org.json.JSONObject

/**
 * Reads events.jsonl and shows flagged entries newest-first — this is the
 * "registo dos IPs a tentar entrar" the user asked for, read directly from
 * the same log file vpnmonitor/wifisecurity/arpmonitor/rootdetection all
 * write to, so nothing here is a separate source of truth.
 */
class ReportActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 64, 32, 32)
        }

        val events = EventLogger(this).readAll()
            .mapNotNull { line -> runCatching { JSONObject(line) }.getOrNull() }
            .filter { it.optString("severity") != "info" }
            .reversed()

        if (events.isEmpty()) {
            container.addView(TextView(this).apply {
                text = "Sem eventos de aviso ou críticos registados ainda."
            })
        }

        for (event in events) {
            container.addView(buildEventRow(event))
        }

        setContentView(ScrollView(this).apply { addView(container) })
    }

    private fun buildEventRow(event: JSONObject): TextView {
        val severity = event.optString("severity")
        val timestamp = event.optString("timestamp")
        val message = event.optString("message")
        val extra = event.optJSONObject("extra")
        val destination = extra?.optString("destination")
        val port = extra?.optString("port")

        val detail = buildString {
            append(message)
            if (!destination.isNullOrBlank()) {
                append(" [")
                append(destination)
                if (!port.isNullOrBlank()) append(":$port")
                append("]")
            }
        }

        return TextView(this).apply {
            text = "$timestamp — $detail"
            setTextColor(if (severity == "critico") Color.RED else Color.rgb(180, 120, 0))
            setPadding(0, 16, 0, 16)
        }
    }
}
