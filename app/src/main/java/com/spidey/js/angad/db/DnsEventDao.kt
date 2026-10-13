package com.spidey.js.angad.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface DnsEventDao {
    @Insert
    suspend fun insert(event: DnsEvent)

    @Query("SELECT * FROM dns_events ORDER BY timestamp DESC LIMIT 100")
    fun getAllEvents(): Flow<List<DnsEvent>>

    @Query("SELECT * FROM dns_events ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int): Flow<List<DnsEvent>>

    @Query("SELECT * FROM dns_events WHERE isThreat = 1 ORDER BY timestamp DESC LIMIT 200")
    fun getThreatLogs(): Flow<List<DnsEvent>>

    @Query("SELECT * FROM dns_events WHERE isThreat = 1 ORDER BY timestamp DESC LIMIT :limit")
    fun getThreatLogs(limit: Int): Flow<List<DnsEvent>>
    
    @Query("SELECT COUNT(*) FROM dns_events")
    fun getTotalCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM dns_events WHERE isThreat = 1")
    fun getBlockedCount(): Flow<Int>

    @Query("SELECT COUNT(DISTINCT appPackage) FROM dns_events")
    fun getActiveAppsCount(): Flow<Int>

    @Query("DELETE FROM dns_events WHERE id NOT IN (SELECT id FROM dns_events ORDER BY timestamp DESC LIMIT :keepCount)")
    suspend fun pruneOldEvents(keepCount: Int): Int

    @Query("DELETE FROM dns_events")
    suspend fun clearAll()
}
