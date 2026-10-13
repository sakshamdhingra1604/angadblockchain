package com.spidey.js.angad.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spidey.js.angad.db.AngadDatabase
import com.spidey.js.angad.db.DnsEvent
import com.spidey.js.angad.ui.components.DivineBackground
import com.spidey.js.angad.ui.theme.*

@Composable
fun TrafficMonitorScreen() {
    val context = LocalContext.current
    val database = AngadDatabase.getDatabase(context)
    val dnsEvents by database.dnsEventDao().getAllEvents().collectAsState(initial = emptyList())

    var selectedEvent by remember { mutableStateOf<DnsEvent?>(null) }

    Box(modifier = Modifier.fillMaxSize()) {
        DivineBackground()
        
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp)
        ) {
            Text(
                "NET-CHAKRA",
                style = MaterialTheme.typography.displayMedium.copy(
                    fontSize = 28.sp, fontWeight = FontWeight.Black, color = RoyalGold, letterSpacing = 2.sp
                )
            )
            Text("FLOW OF DIGITAL ENERGY", style = MaterialTheme.typography.labelSmall, color = DivineSaffron)

            Spacer(modifier = Modifier.height(24.dp))

            // Real-data Activity Chart - shows last 12 events' risk scores as bars
            val recentScores = dnsEvents.take(12).map { it.riskScore.toFloat() }.let { scores ->
                if (scores.size < 12) scores + List(12 - scores.size) { 0.05f } else scores
            }
            Card(
                modifier = Modifier.fillMaxWidth().height(160.dp),
                colors = CardDefaults.cardColors(containerColor = TempleSurface),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.fillMaxSize().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("ACTIVITY INTENSITY", style = MaterialTheme.typography.labelSmall, color = TextMuted)
                        Text(
                            text = "LIVE",
                            style = MaterialTheme.typography.labelSmall,
                            color = RoyalGold,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.weight(1f))
                    Row(
                        modifier = Modifier.fillMaxWidth().height(60.dp),
                        verticalAlignment = Alignment.Bottom,
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        recentScores.reversed().forEach { score ->
                            val barColor = when {
                                score > 0.8f -> LavaCrimson
                                score > 0.5f -> DivineSaffron
                                else -> RoyalGold
                            }
                            Box(
                                modifier = Modifier
                                    .width(8.dp)
                                    .fillMaxHeight(maxOf(score, 0.08f))
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(Brush.verticalGradient(listOf(barColor, barColor.copy(alpha = 0.4f))))
                            )
                        }
                    }
                    Spacer(modifier = Modifier.weight(1f))
                    Text(
                        text = "Red = Threat  •  Yellow = Warn  •  Gold = Safe",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        fontSize = 9.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text("SIGHTED DOMAINS", style = MaterialTheme.typography.titleSmall, color = AncientWhite, letterSpacing = 1.sp)
            Text(
                text = "${dnsEvents.count { it.isThreat }} BLOCKED  •  ${dnsEvents.count { !it.isThreat }} ALLOWED",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted
            )
            Spacer(modifier = Modifier.height(12.dp))

            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(dnsEvents, key = { it.id }) { event ->
                    DivineDnsRow(event) { selectedEvent = event }
                }
            }
        }
    }

    selectedEvent?.let {
        SecurityInsightSheet(event = it) { selectedEvent = null }
    }
}

@Composable
fun DivineDnsRow(event: DnsEvent, onClick: () -> Unit) {
    val riskColor = when {
        event.riskScore > 0.8 -> LavaCrimson
        event.riskScore > 0.5 -> DivineSaffron
        else -> RoyalGold
    }
    val statusLabel = when {
        event.isThreat -> "BLOCK"
        event.riskScore > 0.35 -> "WARN"
        else -> "STABLE"
    }
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = TempleSurface.copy(0.6f)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            // Risk color indicator bar
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .height(36.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(riskColor.copy(alpha = 0.8f))
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = event.domain, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold, color = AncientWhite)
                Text(text = "${event.appLabel} • ${event.queryType}", style = MaterialTheme.typography.bodySmall, color = TextMuted)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = riskColor
                )
                if (event.riskScore > 0.0) {
                    Text(
                        text = "${(event.riskScore * 100).toInt()}%",
                        style = MaterialTheme.typography.labelSmall,
                        color = riskColor.copy(alpha = 0.7f),
                        fontSize = 9.sp
                    )
                }
            }
        }
    }
}
