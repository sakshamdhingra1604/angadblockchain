package com.spidey.js.angad.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spidey.js.angad.ui.components.DivineBackground
import com.spidey.js.angad.ui.components.DivineStatCard
import com.spidey.js.angad.ui.theme.*
import com.spidey.js.angad.util.BlockchainClient
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun BlockchainDashboardScreen() {
    var stats by remember { mutableStateOf<BlockchainClient.BlockchainStats?>(null) }
    var chain by remember { mutableStateOf<List<BlockchainClient.Block>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var isError by remember { mutableStateOf(false) }

    fun refreshData() {
        isLoading = true
        isError = false
        BlockchainClient.getStats { s -> 
            stats = s
            if (s == null) isError = true
        }
        BlockchainClient.getChain { c -> 
            chain = c?.reversed() ?: emptyList()
            isLoading = false
            if (c == null) isError = true
        }
    }

    LaunchedEffect(Unit) {
        refreshData()
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DivineBackground()
        
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        "DHARMA-LEDGER",
                        style = MaterialTheme.typography.displayMedium.copy(
                            fontSize = 28.sp, fontWeight = FontWeight.Black, color = RoyalGold, letterSpacing = 2.sp
                        )
                    )
                    Text("GLOBAL THREAT CONSENSUS", style = MaterialTheme.typography.labelSmall, color = DivineSaffron)
                }
                IconButton(onClick = { refreshData() }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = RoyalGold)
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            if (isLoading && stats == null) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = RoyalGold)
                }
            } else if (isError && stats == null) {
                BlockchainErrorState { refreshData() }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(20.dp),
                    contentPadding = PaddingValues(bottom = 32.dp)
                ) {
                    item {
                        BlockchainStatsSection(stats)
                    }

                    item {
                        Text(
                            "RECENT BLOCKS",
                            style = MaterialTheme.typography.titleSmall,
                            color = AncientWhite,
                            letterSpacing = 1.sp
                        )
                    }

                    items(chain, key = { it.index }) { block ->
                        BlockItem(block)
                    }
                }
            }
        }
    }
}

@Composable
fun BlockchainStatsSection(stats: BlockchainClient.BlockchainStats?) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        DivineStatCard("Blocks", stats?.blockCount?.toString() ?: "0", Modifier.weight(1f), RoyalGold)
        DivineStatCard("Threats", stats?.totalTx?.toString() ?: "0", Modifier.weight(1f), LavaCrimson)
        DivineStatCard("Diff", stats?.difficulty?.toString() ?: "0", Modifier.weight(1f), DivineSaffron)
    }
}

@Composable
fun BlockItem(block: BlockchainClient.Block) {
    val timeString = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()).format(Date(block.timestamp * 1000))
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = TempleSurface.copy(0.6f)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier.size(40.dp).clip(CircleShape).background(RoyalGold.copy(0.1f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Block, contentDescription = null, tint = RoyalGold, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Block #${block.index}", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold, color = AncientWhite)
                    Text(timeString, style = MaterialTheme.typography.bodySmall, color = TextMuted)
                }
                Text(
                    text = "${block.transactions.size} TX",
                    style = MaterialTheme.typography.labelSmall,
                    color = DivineSaffron,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.background(DivineSaffron.copy(0.1f), RoundedCornerShape(4.dp)).padding(horizontal = 8.dp, vertical = 2.dp)
                )
            }
            
            if (block.transactions.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                HorizontalDivider(color = AncientWhite.copy(0.05f))
                Spacer(modifier = Modifier.height(12.dp))
                
                block.transactions.take(3).forEach { tx ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(tx.domain, style = MaterialTheme.typography.bodySmall, color = AncientWhite, fontWeight = FontWeight.SemiBold)
                            if (tx.ip.isNotEmpty()) {
                                Text(tx.ip, style = MaterialTheme.typography.labelSmall, color = TextMuted)
                            }
                        }
                        Text(
                            tx.category.uppercase(),
                            style = MaterialTheme.typography.labelSmall,
                            color = when(tx.category.lowercase()) {
                                "safe" -> RoyalGold
                                else -> LavaCrimson
                            },
                            fontSize = 9.sp
                        )
                    }
                }
                
                if (block.transactions.size > 3) {
                    Text(
                        "+ ${block.transactions.size - 3} more transactions",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                "Hash: ${block.hash.take(24)}...",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
                fontSize = 8.sp
            )
        }
    }
}

@Composable
fun BlockchainErrorState(onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            Icons.Default.Block,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = LavaCrimson.copy(alpha = 0.5f)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            "LEDGER DISCONNECTED",
            style = MaterialTheme.typography.titleMedium,
            color = LavaCrimson,
            fontWeight = FontWeight.Bold
        )
        Text(
            "The blockchain node is currently unreachable.\nLocal protection is still active.",
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(
            onClick = onRetry,
            colors = ButtonDefaults.buttonColors(containerColor = RoyalGold)
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("RECONNECT", color = DeepEarth, fontWeight = FontWeight.Bold)
        }
    }
}
