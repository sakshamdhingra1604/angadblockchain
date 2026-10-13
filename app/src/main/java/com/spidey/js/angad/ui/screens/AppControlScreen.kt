package com.spidey.js.angad.ui.screens

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spidey.js.angad.ui.components.DivineBackground
import com.spidey.js.angad.ui.theme.*
import com.spidey.js.angad.util.PreferencesManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppData(val name: String, val packageName: String, val isSystem: Boolean)

// In-memory cache so subsequent tab navigations are instantaneous
private var cachedApps: List<AppData>? = null

@Composable
fun AppControlScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefManager = remember { PreferencesManager(context) }
    val blockedPackages by prefManager.blockedPackages.collectAsState(initial = emptySet())
    
    var searchQuery by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf("All") }
    val filters = listOf("All", "Allowed", "Blocked", "System")

    var apps by remember { mutableStateOf<List<AppData>>(cachedApps ?: emptyList()) }
    var isLoading by remember { mutableStateOf(cachedApps == null) }

    LaunchedEffect(Unit) {
        if (cachedApps == null) {
            withContext(Dispatchers.IO) {
                val pm = context.packageManager
                // Flag 0 avoids loading metadata bundles for all apps (10x faster)
                val list = pm.getInstalledApplications(0)
                    .filter { it.packageName != context.packageName }
                    .map { app ->
                        AppData(
                            name = pm.getApplicationLabel(app).toString(),
                            packageName = app.packageName,
                            isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                        )
                    }.sortedBy { it.name.lowercase() }
                cachedApps = list
                withContext(Dispatchers.Main) {
                    apps = list
                    isLoading = false
                }
            }
        }
    }

    val filteredApps = remember(apps, searchQuery, selectedFilter, blockedPackages) {
        apps.filter { app ->
            val matchesSearch = app.name.contains(searchQuery, ignoreCase = true) ||
                    app.packageName.contains(searchQuery, ignoreCase = true)
            val matchesFilter = when (selectedFilter) {
                "Allowed" -> !blockedPackages.contains(app.packageName)
                "Blocked" -> blockedPackages.contains(app.packageName)
                "System" -> app.isSystem
                else -> true
            }
            matchesSearch && matchesFilter
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DivineBackground()
        
        Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            Text(
                "DHARMA ARMORY",
                style = MaterialTheme.typography.headlineMedium.copy(
                    fontWeight = FontWeight.Black, color = RoyalGold, letterSpacing = 2.sp
                )
            )

            Text("MANAGE APP PERMISSIONS", style = MaterialTheme.typography.labelSmall, color = DivineSaffron)

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Search scroll of apps...", color = TextMuted) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = RoyalGold) },
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = RoyalGold,
                    unfocusedBorderColor = TempleSurface,
                    cursorColor = RoyalGold
                )
            )

            Spacer(modifier = Modifier.height(16.dp))

            ScrollableTabRow(
                selectedTabIndex = filters.indexOf(selectedFilter),
                edgePadding = 0.dp,
                containerColor = Color.Transparent,
                divider = {},
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[filters.indexOf(selectedFilter)]),
                        color = RoyalGold
                    )
                }
            ) {
                filters.forEach { filter ->
                    Tab(
                        selected = selectedFilter == filter,
                        onClick = { selectedFilter = filter },
                        text = { Text(filter, color = if (selectedFilter == filter) RoyalGold else TextMuted) }
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (isLoading) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = RoyalGold)
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            "Scanning installed armory...",
                            color = TextMuted,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            } else if (filteredApps.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Text("No applications found.", color = TextMuted)
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        DivineAppRow(app, blockedPackages.contains(app.packageName)) { isBlocked ->
                            scope.launch { prefManager.togglePackageBlock(app.packageName, isBlocked) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun DivineAppRow(app: AppData, isBlocked: Boolean, onToggle: (Boolean) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = TempleSurface.copy(0.8f)),
        shape = RoundedCornerShape(topStart = 16.dp, bottomEnd = 16.dp)
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier.size(44.dp).clip(CircleShape).background(RoyalGold.copy(0.1f)),
                contentAlignment = Alignment.Center
            ) {
                val initialChar = app.name.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
                Text(initialChar, color = RoyalGold, fontWeight = FontWeight.Bold)
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = app.name, style = MaterialTheme.typography.titleMedium, color = AncientWhite)
                Text(text = app.packageName, style = MaterialTheme.typography.bodySmall, color = TextMuted, maxLines = 1)
            }
            Switch(
                checked = !isBlocked,
                onCheckedChange = { onToggle(!it) },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = RoyalGold,
                    checkedTrackColor = RoyalGold.copy(0.4f),
                    uncheckedThumbColor = LavaCrimson,
                    uncheckedTrackColor = LavaCrimson.copy(0.4f)
                )
            )
        }
    }
}
