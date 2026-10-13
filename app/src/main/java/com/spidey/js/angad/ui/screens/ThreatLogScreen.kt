package com.spidey.js.angad.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spidey.js.angad.db.AngadDatabase
import com.spidey.js.angad.db.DnsEvent
import com.spidey.js.angad.ui.components.DivineBackground
import com.spidey.js.angad.ui.theme.*
import com.spidey.js.angad.util.PreferencesManager
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun ThreatLogScreen() {
    val context = LocalContext.current
    val database = AngadDatabase.getDatabase(context)
    val threatLogs by database.dnsEventDao().getThreatLogs().collectAsState(initial = emptyList())
    
    var selectedEvent by remember { mutableStateOf<DnsEvent?>(null) }

    Box(modifier = Modifier.fillMaxSize()) {
        DivineBackground()
        
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp)
        ) {
            Text(
                "ADHARMA LOGS",
                style = MaterialTheme.typography.displayMedium.copy(
                    fontSize = 28.sp, fontWeight = FontWeight.Black, color = LavaCrimson, letterSpacing = 2.sp
                )
            )
            Text("CAPTURED THREATS & BLOCKS", style = MaterialTheme.typography.labelSmall, color = TextMuted)

            Spacer(modifier = Modifier.height(24.dp))

            if (threatLogs.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("The network is pure. No threats detected.", color = TextMuted)
                }
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    items(threatLogs, key = { it.id }) { log ->
                        DivineThreatItem(log) { selectedEvent = log }
                    }
                }
            }
        }
    }

    selectedEvent?.let {
        SecurityInsightSheet(event = it) { selectedEvent = null }
    }
}

@Composable
fun DivineThreatItem(log: DnsEvent, onClick: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefManager = remember { PreferencesManager(context) }
    
    val riskColor = when {
        log.riskScore > 0.8 -> LavaCrimson
        log.riskScore > 0.5 -> DivineSaffron
        else -> RoyalGold
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = TempleSurface.copy(0.9f)),
        shape = RoundedCornerShape(topStart = 20.dp, bottomEnd = 20.dp)
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = null,
                tint = riskColor,
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = log.domain, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = AncientWhite)
                val timeString = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(log.timestamp))
                Text(text = "${log.threatType ?: "Suspicious"} • $timeString", style = MaterialTheme.typography.bodySmall, color = TextMuted)
            }
            Surface(
                color = riskColor.copy(alpha = 0.2f),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(
                    text = if (log.riskScore > 0.8) "CRITICAL" else "MEDIUM",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = riskColor,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
