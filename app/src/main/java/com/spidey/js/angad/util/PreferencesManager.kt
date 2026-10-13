package com.spidey.js.angad.util

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

class PreferencesManager(private val context: Context) {

    companion object {
        private val BLOCKED_PACKAGES = stringSetPreferencesKey("blocked_packages")
        private val ALLOWLIST_DOMAINS = stringSetPreferencesKey("allowlist_domains")
        private val DENYLIST_DOMAINS = stringSetPreferencesKey("denylist_domains")
        private val SENSITIVITY_THRESHOLD = floatPreferencesKey("sensitivity_threshold")
        private val AUTO_RESTART = booleanPreferencesKey("auto_restart")
        private val NOTIFICATIONS_ENABLED = booleanPreferencesKey("notifications_enabled")
        private val VPN_ENABLED_STATE = booleanPreferencesKey("vpn_enabled_state")
    }

    val blockedPackages: Flow<Set<String>> = context.dataStore.data.map { it[BLOCKED_PACKAGES] ?: emptySet() }
    val allowlistDomains: Flow<Set<String>> = context.dataStore.data.map { it[ALLOWLIST_DOMAINS] ?: emptySet() }
    val denylistDomains: Flow<Set<String>> = context.dataStore.data.map { it[DENYLIST_DOMAINS] ?: emptySet() }
    val sensitivityThreshold: Flow<Float> = context.dataStore.data.map { it[SENSITIVITY_THRESHOLD] ?: 0.70f }
    val autoRestart: Flow<Boolean> = context.dataStore.data.map { it[AUTO_RESTART] ?: true }
    val notificationsEnabled: Flow<Boolean> = context.dataStore.data.map { it[NOTIFICATIONS_ENABLED] ?: true }
    val vpnEnabledState: Flow<Boolean> = context.dataStore.data.map { it[VPN_ENABLED_STATE] ?: false }

    suspend fun togglePackageBlock(packageName: String, block: Boolean) {
        context.dataStore.edit { prefs ->
            val current = prefs[BLOCKED_PACKAGES] ?: emptySet()
            val next = if (block) current + packageName else current - packageName
            prefs[BLOCKED_PACKAGES] = next
        }
    }

    suspend fun setSensitivity(value: Float) {
        context.dataStore.edit { it[SENSITIVITY_THRESHOLD] = value }
    }

    suspend fun setAutoRestart(enabled: Boolean) {
        context.dataStore.edit { it[AUTO_RESTART] = enabled }
    }

    suspend fun setNotificationsEnabled(enabled: Boolean) {
        context.dataStore.edit { it[NOTIFICATIONS_ENABLED] = enabled }
    }

    suspend fun setVpnEnabledState(enabled: Boolean) {
        context.dataStore.edit { it[VPN_ENABLED_STATE] = enabled }
    }

    suspend fun addToAllowlist(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[ALLOWLIST_DOMAINS] ?: emptySet()
            prefs[ALLOWLIST_DOMAINS] = current + domain
        }
    }

    suspend fun removeFromAllowlist(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[ALLOWLIST_DOMAINS] ?: emptySet()
            prefs[ALLOWLIST_DOMAINS] = current - domain
        }
    }
}
