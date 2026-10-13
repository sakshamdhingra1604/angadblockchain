package com.spidey.js.angad.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spidey.js.angad.ui.components.DivineBackground
import com.spidey.js.angad.ui.theme.*
import kotlinx.coroutines.delay

@Composable
fun AngadSplashScreen(onFinish: () -> Unit) {
    var startFadeOut by remember { mutableStateOf(false) }

    val alphaAnim by animateFloatAsState(
        targetValue = if (startFadeOut) 0f else 1f,
        animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing),
        label = "splashAlpha"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "divinePulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.94f,
        targetValue = 1.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    val auraAlpha by infiniteTransition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.65f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "auraAlpha"
    )

    val haloRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(8000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "haloRotation"
    )

    LaunchedEffect(Unit) {
        delay(1600)
        startFadeOut = true
        delay(450)
        onFinish()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .alpha(alphaAnim)
    ) {
        DivineBackground()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(modifier = Modifier.weight(1f))

            // Central Glowing Shield Emblem
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(150.dp)
                    .scale(pulseScale)
            ) {
                // Outer Radial Glow
                Canvas(modifier = Modifier.fillMaxSize()) {
                    drawCircle(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                RoyalGold.copy(alpha = auraAlpha),
                                DivineSaffron.copy(alpha = auraAlpha * 0.4f),
                                Color.Transparent
                            )
                        )
                    )
                    // Rotating Halo Ring
                    drawCircle(
                        color = RoyalGold.copy(alpha = 0.35f),
                        radius = size.minDimension / 2.3f,
                        style = Stroke(
                            width = 2.dp.toPx(),
                            cap = StrokeCap.Round
                        )
                    )
                }

                // Inner Emblem Container
                Box(
                    modifier = Modifier
                        .size(86.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.linearGradient(
                                listOf(TempleSurface, DeepEarth)
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "Angad Shield",
                        tint = RoyalGold,
                        modifier = Modifier.size(52.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            // Main Brand Title
            Text(
                text = "ANGAD",
                style = MaterialTheme.typography.displayMedium.copy(
                    fontSize = 38.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 6.sp,
                    color = RoyalGold
                )
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "DHARMA PROTECTION ENGINE",
                style = MaterialTheme.typography.labelSmall.copy(
                    color = DivineSaffron,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.5.sp
                )
            )

            Spacer(modifier = Modifier.weight(1f))

            // Subtle Footer
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .background(TempleSurface.copy(alpha = 0.6f))
                    .padding(horizontal = 14.dp, vertical = 6.dp)
            ) {
                Text(
                    text = "AI TRI-MODEL SHIELD • SOVEREIGN FIREWALL",
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = TextMuted,
                        fontSize = 10.sp,
                        letterSpacing = 1.sp
                    )
                )
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
