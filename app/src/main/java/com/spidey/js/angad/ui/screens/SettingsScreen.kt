package com.spidey.js.angad.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
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
import com.spidey.js.angad.ui.theme.*
import com.spidey.js.angad.util.PreferencesManager
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefManager = remember { PreferencesManager(context) }
    val sensitivity by prefManager.sensitivityThreshold.collectAsState(initial = 0.75f)
    val notificationsEnabled by prefManager.notificationsEnabled.collectAsState(initial = true)
    val autoRestart by prefManager.autoRestart.collectAsState(initial = true)

    Box(modifier = Modifier.fillMaxSize().background(DeepEarth)) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            Text(
                "SHIELD CONFIG",
                style = MaterialTheme.typography.displayMedium.copy(
                    fontSize = 28.sp, fontWeight = FontWeight.Black, color = RoyalGold, letterSpacing = 2.sp
                )
            )
            Text("FINE-TUNE YOUR PROTECTION", style = MaterialTheme.typography.labelSmall, color = DivineSaffron)

            Spacer(modifier = Modifier.height(32.dp))

            SettingsSection("SECURITY MODEL") {
                Column {
                    Text("Phishing Detection Sensitivity", style = MaterialTheme.typography.titleMedium, color = AncientWhite)
                    Text("Higher sensitivity may increase false positives", style = MaterialTheme.typography.bodySmall, color = TextMuted)
                    Slider(
                        value = sensitivity,
                        onValueChange = { scope.launch { prefManager.setSensitivity(it) } },
                        colors = SliderDefaults.colors(
                            thumbColor = RoyalGold,
                            activeTrackColor = RoyalGold,
                            inactiveTrackColor = Color.DarkGray
                        ),
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                    Text(
                        text = "${(sensitivity * 100).toInt()}% Confidence Threshold",
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.align(Alignment.End),
                        color = RoyalGold
                    )
                }
            }

            SettingsSection("PREFERENCES") {
                SettingsToggleItem("Real-time Notifications", "Alert on threat detection", notificationsEnabled) {
                    scope.launch { prefManager.setNotificationsEnabled(it) }
                }
                SettingsToggleItem("Auto-restart on Boot", "Keep protection active after restart", autoRestart) {
                    scope.launch { prefManager.setAutoRestart(it) }
                }
            }

            SettingsSection("DATABASE & STORAGE") {
                SettingsItem("Auto-Retention Policy", "Active (Capped at 2,000 events)")
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(text = "Clear Event Logs", style = MaterialTheme.typography.titleMedium, color = AncientWhite)
                        Text(text = "Purge local DNS queries and threat logs", style = MaterialTheme.typography.bodySmall, color = TextMuted)
                    }
                    Button(
                        onClick = {
                            scope.launch {
                                AngadDatabase.getDatabase(context).dnsEventDao().clearAll()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = LavaCrimson.copy(alpha = 0.8f)),
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text("Purge", color = AncientWhite, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }

            SettingsSection("SYSTEM") {
                SettingsItem("Main Model", "CICIDS2017 Core (65 Params)")
                SettingsItem("Ensemble Model", "ShieldNet v2.0 (41 Features - Safe Corpus)")
                SettingsItem("Check for Updates", "Last checked: Today, 10:45 AM")
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text(text = "Angad Firewall v1.0.0", style = MaterialTheme.typography.labelSmall, modifier = Modifier.align(Alignment.CenterHorizontally), color = TextMuted)
        }
    }
}

@Composable
fun SettingsSection(title: String, content: @Composable () -> Unit) {
    Column(modifier = Modifier.padding(bottom = 24.dp)) {
        Text(text = title, style = MaterialTheme.typography.labelLarge, color = RoyalGold, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 12.dp))
        Card(colors = CardDefaults.cardColors(containerColor = TempleSurface), shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) { content() }
        }
    }
}

@Composable
fun SettingsItem(title: String, subtitle: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Column {
            Text(text = title, style = MaterialTheme.typography.titleMedium, color = AncientWhite)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = TextMuted)
        }
        Icon(Icons.Default.ChevronRight, contentDescription = null, tint = MutedGold)
    }
}

@Composable
fun SettingsToggleItem(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium, color = AncientWhite)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = TextMuted)
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = RoyalGold,
                checkedTrackColor = RoyalGold.copy(alpha = 0.4f),
                uncheckedThumbColor = Color.DarkGray,
                uncheckedTrackColor = Color.Black
            )
        )
    }
}
