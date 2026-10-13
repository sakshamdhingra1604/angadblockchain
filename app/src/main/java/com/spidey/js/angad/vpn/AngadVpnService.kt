package com.spidey.js.angad.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.spidey.js.angad.db.AngadDatabase
import com.spidey.js.angad.db.DnsEvent
import com.spidey.js.angad.ml.AngadModelEngine
import com.spidey.js.angad.util.BlockchainClient
import com.spidey.js.angad.util.PacketParser
import com.spidey.js.angad.util.PreferencesManager
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer

class AngadVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var database: AngadDatabase
    private lateinit var connectivityManager: ConnectivityManager
    private lateinit var prefManager: PreferencesManager
    private var modelEngine: AngadModelEngine? = null
    private val blockedPackages = HashSet<String>()
    private val tunLock = Any()
    private val eventInsertCounter = java.util.concurrent.atomic.AtomicInteger(0)
    private var lastGlobalNotifTime = 0L

    companion object {
        private const val TAG = "AngadVpnService"
        private const val CHANNEL_ID = "angad_vpn_channel"
        private const val THREAT_CHANNEL_ID = "angad_threat_alerts"
        private const val BLOCK_NOTIF_ID = 101
        const val ACTION_STOP = "com.spidey.js.angad.vpn.STOP"
        
        private val _isServiceRunning = MutableStateFlow(false)
        val isServiceRunning = _isServiceRunning.asStateFlow()
        
        private const val REAL_DNS_PRIMARY = "8.8.4.4"
        private const val REAL_DNS_FALLBACK = "1.1.1.1"
        private const val REAL_DNS_IP = REAL_DNS_PRIMARY
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        database = AngadDatabase.getDatabase(this)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        prefManager = PreferencesManager(this)
        modelEngine = AngadModelEngine(this)

        serviceScope.launch {
            prefManager.blockedPackages.collect { packages ->
                synchronized(blockedPackages) {
                    blockedPackages.clear()
                    blockedPackages.addAll(packages)
                    Log.d(TAG, "Updated blocked packages: ${blockedPackages.size}")
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        startVpn()
        return START_STICKY
    }

    private val notificationDebounce = android.util.LruCache<String, Long>(100)

    private fun startVpn() {
        startForeground(1, createNotification())
        try {
            vpnInterface = Builder()
                .addAddress("10.0.0.2", 32)
                .addDnsServer("10.0.0.2")
                .addDnsServer("8.8.8.8")
                .addRoute("10.0.0.2", 32)
                .addRoute("8.8.8.8", 32)
                .addRoute("8.8.4.4", 32)
                .addRoute("1.1.1.1", 32)
                .addRoute("1.0.0.1", 32)
                .addRoute("9.9.9.9", 32)
                .setMtu(1500)
                .setSession("Angad Protection")
                .setBlocking(false) // Non-blocking for speed
                .establish()

            if (vpnInterface != null) {
                _isServiceRunning.value = true
                serviceScope.launch {
                    try {
                        database.dnsEventDao().pruneOldEvents(2000)
                    } catch (e: Exception) {
                        Log.e(TAG, "Startup pruning failed", e)
                    }
                }
                startPacketLoop()
            } else {
                stopSelf()
            }
        } catch (e: Exception) {
            stopSelf()
        }
    }

    private fun startPacketLoop() {
        serviceScope.launch(Dispatchers.IO) {
            val fd = vpnInterface?.fileDescriptor ?: return@launch
            val inputStream = FileInputStream(fd)
            val outputStream = FileOutputStream(fd)
            val buffer = ByteBuffer.allocate(Short.MAX_VALUE.toInt())
            
            try {
                while (isActive) {
                    val length = inputStream.read(buffer.array())
                    if (length > 0) {
                        val packetData = buffer.array().copyOf(length)
                        handlePacket(packetData, length, outputStream)
                        buffer.clear()
                    } else if (length == -1) break
                }
            } catch (e: Exception) {
                if (isActive) Log.e(TAG, "Fatal loop error", e)
            } finally {
                _isServiceRunning.value = false
            }
        }
    }

    private suspend fun handlePacket(data: ByteArray, length: Int, outputStream: FileOutputStream) {
        if (length < 28) return
        
        val ihl = (data[0].toInt() and 0x0F) * 4
        val protocol = data[9].toInt() and 0xFF
        val srcIp = InetAddress.getByAddress(data.sliceArray(12..15))
        val dstIp = InetAddress.getByAddress(data.sliceArray(16..19))
        
        val srcPort: Int
        val dstPort: Int
        if (protocol == 17) { // UDP (DNS)
            srcPort = ((data[ihl].toInt() and 0xFF) shl 8) or (data[ihl + 1].toInt() and 0xFF)
            dstPort = ((data[ihl + 2].toInt() and 0xFF) shl 8) or (data[ihl + 3].toInt() and 0xFF)
            
            if (dstPort == 53) {
                val dnsOffset = ihl + 8
                val dnsLen = length - dnsOffset
                val dnsQuestion = PacketParser.parseDnsDomain(data, dnsOffset, dnsLen)
                
                if (dnsQuestion != null) {
                    // Extract raw DNS payload bytes (after IP+UDP header) for PayloadNet classifier
                    val rawDnsBytes = data.sliceArray(dnsOffset until minOf(dnsOffset + dnsLen, length))
                    val result = getFullVerdict(dnsQuestion.domain, rawDnsBytes)
                    val uid = getUidForConnection(srcIp, srcPort, dstIp, dstPort, "UDP")
                    val appInfo = getAppInfoForUid(uid)
                    
                    val isAppBlocked = synchronized(blockedPackages) { blockedPackages.contains(appInfo.packageName) }

                    if (isAppBlocked || result.isBlocked) {
                        val finalVerdict = if (isAppBlocked) {
                            result.mlVerdict.copy(classification = "App Restricted", score = 1.0f)
                        } else {
                            result.mlVerdict
                        }
                        logAndNotifyBlock(dnsQuestion.domain, dstIp.hostAddress ?: "", appInfo, finalVerdict)
                        val response = PacketParser.createSinkholeResponse(data, dnsOffset, dnsLen)
                        val ipResponse = buildIpUdpPacket(dstIp, dstPort, srcIp, srcPort, response, response.size)
                        synchronized(tunLock) {
                            outputStream.write(ipResponse)
                        }
                    } else {
                        logDomainEvent(dnsQuestion.domain, dstIp.hostAddress ?: "", "DNS", appInfo, result.mlVerdict, false)
                        // SPEED FIX: Launch proxy in a separate job so we don't block the loop
                        serviceScope.launch {
                            proxyDnsQuery(data, dnsOffset, dnsLen, srcIp, srcPort, dstIp, dstPort, outputStream)
                        }
                    }
                }
            }
        }
    }

    private data class VerdictResult(val mlVerdict: AngadModelEngine.ModelVerdict, val isBlocked: Boolean)

    private suspend fun getFullVerdict(domain: String, rawDnsBytes: ByteArray? = null): VerdictResult {
        if (prefManager.allowlistDomains.first().contains(domain)) 
            return VerdictResult(AngadModelEngine.ModelVerdict(0f, "Allowlist"), false)
        if (prefManager.denylistDomains.first().contains(domain)) 
            return VerdictResult(AngadModelEngine.ModelVerdict(1f, "Denylist"), true)
        
        val ml = modelEngine?.predict(domain, 0, false, rawDnsBytes) ?: AngadModelEngine.ModelVerdict(0f, "Unknown")
        val threshold = prefManager.sensitivityThreshold.first()
        return VerdictResult(ml, ml.score >= threshold)
    }

    private fun checkAndPruneEvents() {
        if (eventInsertCounter.incrementAndGet() % 500 == 0) {
            serviceScope.launch {
                try {
                    database.dnsEventDao().pruneOldEvents(2000)
                } catch (e: Exception) {
                    Log.e(TAG, "Periodic pruning failed", e)
                }
            }
        }
    }

    private fun logAndNotifyBlock(domain: String, ip: String, app: AppInfo, verdict: AngadModelEngine.ModelVerdict) {
        serviceScope.launch {
            try {
                val metadata = "M1_Score=${"%.2f".format(verdict.model1Score)};M2_Score=${"%.2f".format(verdict.model2Score)};M3_Score=${"%.2f".format(verdict.model3Score)};Reasons=${verdict.reasons.joinToString("|")};Features=${verdict.featureHighlights.map { "${it.key}=${"%.2f".format(it.value)}" }.joinToString(",")}"
                database.dnsEventDao().insert(DnsEvent(
                    domain = domain, appPackage = app.packageName, appLabel = app.label,
                    timestamp = System.currentTimeMillis(), queryType = "BLOCK",
                    isThreat = true, threatType = verdict.classification, riskScore = verdict.score.toDouble(),
                    aiMetadata = metadata
                ))
                Log.d(TAG, "Logged block event for: $domain ($ip)")
                checkAndPruneEvents()
                
                // Report to global blockchain
                BlockchainClient.reportThreat(domain, ip, verdict.classification, verdict.score)
                
                if (prefManager.notificationsEnabled.first()) showBlockNotification(domain, app.label, verdict)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to log block event for $domain", e)
            }
        }
    }

    private fun logDomainEvent(domain: String, ip: String, type: String, app: AppInfo, verdict: AngadModelEngine.ModelVerdict, isBlocked: Boolean) {
        serviceScope.launch {
            try {
                val metadata = "M1_Score=${"%.2f".format(verdict.model1Score)};M2_Score=${"%.2f".format(verdict.model2Score)};M3_Score=${"%.2f".format(verdict.model3Score)};Reasons=${verdict.reasons.joinToString("|")};Features=${verdict.featureHighlights.map { "${it.key}=${"%.2f".format(it.value)}" }.joinToString(",")}"
                database.dnsEventDao().insert(DnsEvent(
                    domain = domain, appPackage = app.packageName, appLabel = app.label,
                    timestamp = System.currentTimeMillis(), queryType = type,
                    isThreat = isBlocked, threatType = verdict.classification, riskScore = verdict.score.toDouble(),
                    aiMetadata = metadata
                ))
                Log.d(TAG, "Logged $type event for: $domain ($ip)")
                checkAndPruneEvents()
                
                if (isBlocked) {
                    BlockchainClient.reportThreat(domain, ip, verdict.classification, verdict.score)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to log $type event for $domain", e)
            }
        }
    }

    private fun showBlockNotification(domain: String, appLabel: String, verdict: AngadModelEngine.ModelVerdict) {
        val now = System.currentTimeMillis()
        val lastDomainTime = notificationDebounce.get(domain) ?: 0L
        if (now - lastDomainTime < 60_000L) {
            // Anti-Spam: Suppress duplicate notification for the same domain within 60 seconds
            return
        }
        // Global Throttle: Prevent rapid sound/buzz bursts if background apps spam queries
        if (now - lastGlobalNotifTime < 8_000L) {
            return
        }
        notificationDebounce.put(domain, now)
        lastGlobalNotifTime = now

        val alertIntent = Intent(this, com.spidey.js.angad.ThreatAlertActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(com.spidey.js.angad.ThreatAlertActivity.EXTRA_DOMAIN, domain)
            putExtra(com.spidey.js.angad.ThreatAlertActivity.EXTRA_APP_LABEL, appLabel)
            putExtra(com.spidey.js.angad.ThreatAlertActivity.EXTRA_RISK_SCORE, verdict.score)
            putExtra(com.spidey.js.angad.ThreatAlertActivity.EXTRA_THREAT_TYPE, verdict.classification)
            putExtra(com.spidey.js.angad.ThreatAlertActivity.EXTRA_REASONS, verdict.reasons.toTypedArray())
        }

        // Tap on notification opens ThreatAlertActivity smoothly
        val contentPendingIntent = PendingIntent.getActivity(
            this,
            domain.hashCode(),
            alertIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, THREAT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("🛡️ Phishing Threat Blocked")
            .setContentText("Blocked $domain accessed by $appLabel")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("Angad blocked suspicious domain $domain (accessed by $appLabel). Tap to view full threat insight or whitelist.")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(contentPendingIntent)
            .setAutoCancel(true)
            .build()

        getSystemService(NotificationManager::class.java)?.notify(domain.hashCode(), notification)
    }

    private suspend fun proxyDnsQuery(
        data: ByteArray,
        dnsOffset: Int,
        dnsLen: Int,
        srcIp: InetAddress,
        srcPort: Int,
        dstIp: InetAddress,
        dstPort: Int,
        outputStream: FileOutputStream
    ) = withContext(Dispatchers.IO) {
        val servers = listOf(REAL_DNS_PRIMARY, REAL_DNS_FALLBACK)
        for (dnsServer in servers) {
            var success = false
            try {
                DatagramSocket().use { socket ->
                    protect(socket)
                    socket.soTimeout = 2500
                    val queryPacket = DatagramPacket(
                        data, dnsOffset, dnsLen,
                        InetAddress.getByName(dnsServer), 53
                    )
                    socket.send(queryPacket)
                    val buffer = ByteArray(4096)
                    val responsePacket = DatagramPacket(buffer, buffer.size)
                    socket.receive(responsePacket)
                    val ipResponse = buildIpUdpPacket(
                        dstIp, dstPort, srcIp, srcPort,
                        responsePacket.data, responsePacket.length
                    )
                    synchronized(tunLock) {
                        outputStream.write(ipResponse)
                    }
                    success = true
                }
            } catch (e: Exception) {
                // Timeout or network error; try fallback DNS server
            }
            if (success) break
        }
    }

    private fun buildIpUdpPacket(srcIp: InetAddress, srcPort: Int, dstIp: InetAddress, dstPort: Int, payload: ByteArray, payloadLen: Int): ByteArray {
        val totalLen = 20 + 8 + payloadLen
        val packet = ByteArray(totalLen)
        val buffer = ByteBuffer.wrap(packet)
        
        // IPv4 Header
        buffer.put(0x45.toByte()) // Version 4, IHL 5
        buffer.put(0.toByte())    // TOS
        buffer.putShort(totalLen.toShort())
        buffer.putShort(0)        // ID
        buffer.putShort(0x4000.toShort()) // Flags: Don't fragment
        buffer.put(64.toByte())   // TTL
        buffer.put(17.toByte())   // Protocol: UDP
        buffer.putShort(0)        // Checksum placeholder
        buffer.put(srcIp.address)
        buffer.put(dstIp.address)
        
        // Calculate IP Checksum
        val ipChecksum = calculateChecksum(packet, 0, 20)
        buffer.putShort(10, ipChecksum)
        
        // UDP Header
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        val udpLen = 8 + payloadLen
        buffer.putShort(udpLen.toShort())
        buffer.putShort(0) // UDP Checksum
        buffer.put(payload, 0, payloadLen)
        
        return packet
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Short {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        var checksum = sum.inv() and 0xFFFF
        if (checksum == 0) checksum = 0xFFFF
        return checksum.toShort()
    }

    private fun getUidForConnection(srcIp: InetAddress, srcPort: Int, dstIp: InetAddress, dstPort: Int, protocol: String): Int {
        try { return connectivityManager.getConnectionOwnerUid(if (protocol == "TCP") 6 else 17, InetSocketAddress(srcIp, srcPort), InetSocketAddress(dstIp, dstPort)) } catch (e: Exception) {}
        return -1
    }

    private fun getAppInfoForUid(uid: Int): AppInfo {
        if (uid <= 0) return AppInfo("unknown", "System")
        val packages = packageManager.getPackagesForUid(uid)
        if (packages != null && packages.isNotEmpty()) {
            val pkg = packages[0]
            return try { AppInfo(pkg, packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()) } catch (e: Exception) { AppInfo(pkg, pkg) }
        }
        return AppInfo("uid_$uid", "UID $uid")
    }

    data class AppInfo(val packageName: String, val label: String)
    private fun stopVpn() {
        serviceScope.cancel(); _isServiceRunning.value = false; modelEngine?.close()
        try { vpnInterface?.close() } catch (e: Exception) {}
        vpnInterface = null; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }
    override fun onRevoke() { stopVpn(); super.onRevoke() }
    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        val vpnChannel = NotificationChannel(CHANNEL_ID, "Angad Protection Status", NotificationManager.IMPORTANCE_LOW)
        val threatChannel = NotificationChannel(THREAT_CHANNEL_ID, "Phishing & Threat Alerts", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Real-time alerts when phishing or scam links are blocked"
            enableVibration(true)
            enableLights(true)
        }
        nm?.createNotificationChannel(vpnChannel)
        nm?.createNotificationChannel(threatChannel)
    }
    private fun createNotification(): Notification {
        val stopIntent = Intent(this, AngadVpnService::class.java).apply { action = ACTION_STOP }
        val stopPI = PendingIntent.getService(this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE)
        val contentPI = PendingIntent.getActivity(this, 0, Intent(this, com.spidey.js.angad.MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID).setContentTitle("Angad Protection Active").setContentText("AI Shield is monitoring threats...").setSmallIcon(android.R.drawable.ic_lock_idle_lock).setOngoing(true).setContentIntent(contentPI).addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPI).build()
    }
    override fun onDestroy() { stopVpn(); super.onDestroy() }
}
