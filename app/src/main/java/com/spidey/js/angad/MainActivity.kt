package com.spidey.js.angad

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.spidey.js.angad.ui.MainNavigation
import com.spidey.js.angad.ui.screens.AngadSplashScreen
import com.spidey.js.angad.ui.theme.AngadTheme
import com.spidey.js.angad.util.PreferencesManager
import com.spidey.js.angad.vpn.AngadVpnService
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var prefManager: PreferencesManager

    private val notifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefManager = PreferencesManager(this)
        enableEdgeToEdge()
        setContent {
            AngadTheme {
                var showSplash by remember { mutableStateOf(true) }
                if (showSplash) {
                    AngadSplashScreen(onFinish = { showSplash = false })
                } else {
                    MainNavigation()
                }
            }
        }

        checkBatteryOptimization()
        checkNotificationPermission()
        checkOverlayPermission()

        lifecycleScope.launch {
            AngadVpnService.isServiceRunning.collectLatest { running ->
                prefManager.setVpnEnabledState(running)
            }
        }
    }

    private fun checkNotificationPermission() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                notifPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun checkOverlayPermission() {
        if (!Settings.canDrawOverlays(this)) {
            try {
                val intent = Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$packageName")
                )
                startActivity(intent)
            } catch (e: Exception) {
                // Ignore if not supported
            }
        }
    }

    private fun checkBatteryOptimization() {
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
            try {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            } catch (e: Exception) {
                // Not supported or failed
            }
        }
    }

    fun toggleVpn(enable: Boolean) {
        if (enable) {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnPrepareLauncher.launch(intent)
            } else {
                startVpnService()
            }
        } else {
            stopVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, AngadVpnService::class.java)
        startForegroundService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, AngadVpnService::class.java).apply {
            action = AngadVpnService.ACTION_STOP
        }
        startService(intent)
    }

    override fun onResume() {
        super.onResume()
        // Check if VPN was revoked while app was in background
        if (VpnService.prepare(this) != null && AngadVpnService.isServiceRunning.value) {
            Toast.makeText(this, "VPN permission was revoked", Toast.LENGTH_SHORT).show()
            stopVpnService()
        }
    }
}