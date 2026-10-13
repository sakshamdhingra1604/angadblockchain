package com.spidey.js.angad.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spidey.js.angad.MainActivity
import com.spidey.js.angad.db.AngadDatabase
import com.spidey.js.angad.db.DnsEvent
import com.spidey.js.angad.ui.components.DivineBackground
import com.spidey.js.angad.ui.components.DivineStatCard
import com.spidey.js.angad.ui.theme.*
import com.spidey.js.angad.vpn.AngadVpnService
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val database = AngadDatabase.getDatabase(context)
    val isVpnActive by AngadVpnService.isServiceRunning.collectAsState()
    
    val recentActivity by database.dnsEventDao().getRecentEvents(10).collectAsState(initial = emptyList())
    val scannedCount by database.dnsEventDao().getTotalCount().collectAsState(initial = 0)
    val blockedCount by database.dnsEventDao().getBlockedCount().collectAsState(initial = 0)
    val activeAppsCount by database.dnsEventDao().getActiveAppsCount().collectAsState(initial = 0)

    var selectedEvent by remember { mutableStateOf<DnsEvent?>(null) }

    Box(modifier = Modifier.fillMaxSize()) {
        DivineBackground()
        
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(32.dp)
        ) {
            item { DivineHeader() }
            
            item {
                DivineShieldToggle(isVpnActive) { enabled ->
                    (context as? MainActivity)?.toggleVpn(enabled)
                }
            }

            item {
                DivineStats(scannedCount, blockedCount, activeAppsCount)
            }

            item {
                ActivityFeedSection(recentActivity) { event ->
                    selectedEvent = event
                }
            }
        }
    }

    selectedEvent?.let {
        SecurityInsightSheet(event = it) { selectedEvent = null }
    }
}

@Composable
fun DivineHeader() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(
                "ANGAD",
                style = MaterialTheme.typography.displayMedium.copy(
                    fontWeight = FontWeight.Black,
                    letterSpacing = 4.sp,
                    color = RoyalGold
                )
            )
            Text(
                "DHARMA PROTECTION ENGINE",
                style = MaterialTheme.typography.labelSmall.copy(
                    color = DivineSaffron,
                    letterSpacing = 2.sp
                )
            )
        }
        Icon(
            Icons.Default.Notifications,
            contentDescription = null,
            tint = RoyalGold,
            modifier = Modifier.size(28.dp)
        )
    }
}

@Composable
fun DivineShieldToggle(isActive: Boolean, onToggle: (Boolean) -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "aura")
    
    // Core pulsating glow
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f, targetValue = 0.6f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = LinearOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "glow"
    )

    val auraScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.15f,
        animationSpec = infiniteRepeatable(
            animation = tween(2500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "auraScale"
    )
    
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(15000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ), label = "rotation"
    )

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(240.dp)) {
            // Background Radial Tejas (Glow)
            Canvas(modifier = Modifier.size(200.dp)) {
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            (if (isActive) RoyalGold else LavaCrimson).copy(alpha = glowAlpha),
                            Color.Transparent
                        )
                    )
                )
            }

            // Divine Aura Rings
            Canvas(modifier = Modifier.fillMaxSize().scale(auraScale).rotate(rotation)) {
                drawArc(
                    brush = Brush.sweepGradient(listOf(RoyalGold.copy(0.1f), DivineSaffron.copy(0.4f), RoyalGold.copy(0.1f))),
                    startAngle = 0f, sweepAngle = 360f, useCenter = false,
                    style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
                )
                // Secondary offset ring
                drawCircle(
                    color = RoyalGold.copy(alpha = 0.2f),
                    radius = size.minDimension / 2.4f,
                    style = Stroke(width = 1.dp.toPx())
                )
            }
            
            // Mandala Background
            Surface(
                modifier = Modifier.size(170.dp).clip(CircleShape),
                color = if (isActive) DivineSaffron.copy(0.15f) else LavaCrimson.copy(0.1f),
                border = null // Clean edge
            ) {
                Box(contentAlignment = Alignment.Center) {
                    IconButton(
                        onClick = { onToggle(!isActive) },
                        modifier = Modifier.size(120.dp)
                    ) {
                        Icon(
                            Icons.Default.Shield,
                            contentDescription = null,
                            modifier = Modifier.size(80.dp),
                            tint = if (isActive) RoyalGold else LavaCrimson
                        )
                    }
                }
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        AnimatedContent(targetState = isActive, label = "status") { active ->
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = if (active) "PROTECTION ACTIVE" else "SHIELD INACTIVE",
                    style = MaterialTheme.typography.headlineSmall.copy(
                        fontWeight = FontWeight.Bold,
                        color = if (active) RoyalGold else LavaCrimson,
                        letterSpacing = 1.sp
                    )
                )
                Text(
                    text = if (active) "Your network is shielded by Dharma" else "Activate to ward off phishing threats",
                    style = MaterialTheme.typography.bodySmall,
                    color = AncientWhite.copy(0.6f)
                )
            }
        }
    }
}

@Composable
fun DivineStats(scanned: Int, blocked: Int, apps: Int) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        DivineStatCard("Scanned", scanned.toString(), Modifier.weight(1f), RoyalGold)
        DivineStatCard("Purged", blocked.toString(), Modifier.weight(1f), LavaCrimson)
        DivineStatCard("Watched", apps.toString(), Modifier.weight(1f), DivineSaffron)
    }
}

@Composable
fun ActivityFeedSection(activities: List<DnsEvent>, onItemClick: (DnsEvent) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp) // Ensures consistent gaps between items
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(bottom = 8.dp) // Adjusted bottom padding
        ) {
            Icon(Icons.Default.History, contentDescription = null, tint = DivineSaffron, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                "RECENT SIGHTINGS",
                style = MaterialTheme.typography.titleSmall,
                color = AncientWhite,
                letterSpacing = 1.5.sp
            )
        }
        
        activities.forEach { event ->
            key(event.id) {
                AnimatedVisibility(
                    visible = true,
                    enter = fadeIn() + slideInHorizontally()
                ) {
                    DivineActivityRow(event) { onItemClick(event) }
                }
            }
        }
    }
}

@Composable
fun DivineActivityRow(event: DnsEvent, onClick: () -> Unit) {
    val timeString = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(event.timestamp))
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = TempleSurface.copy(0.6f)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(44.dp).clip(CircleShape).background(RoyalGold.copy(0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    event.appLabel.firstOrNull()?.toString() ?: "?",
                    color = RoyalGold, fontWeight = FontWeight.Bold
                )
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(event.domain, style = MaterialTheme.typography.bodyMedium, color = AncientWhite, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text(event.appLabel, style = MaterialTheme.typography.bodySmall, color = TextMuted)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    if (event.isThreat) "PURGED" else "ALLOWED",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = if (event.isThreat) LavaCrimson else RoyalGold
                )
                Text(timeString, style = MaterialTheme.typography.labelSmall, color = TextMuted)
            }
        }
    }
}
