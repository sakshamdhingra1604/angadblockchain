package com.spidey.js.angad.util

import android.util.Log
import com.google.gson.Gson
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

object BlockchainClient {
    private const val TAG = "BlockchainClient"
    private const val BASE_URL = "https://cherisher-sprig-amigo.ngrok-free.dev"
    
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()
        
    private val gson = Gson()
    private val JSON = "application/json; charset=utf-8".toMediaType()

    data class TransactionRequest(
        val domain: String,
        val ip: String,
        val category: String,
        val riskScore: Float,
        val reportedBy: String = "Angad-Android-Client",
        val timestamp: Long = System.currentTimeMillis() / 1000
    )

    data class BlockchainStats(
        val blockCount: Int,
        val totalTx: Int,
        val mempoolSize: Int,
        val difficulty: Int,
        val chainSizeBytes: Long,
        val uptimeSeconds: Double
    )

    data class Block(
        val index: Int,
        val timestamp: Long,
        val transactions: List<Transaction>,
        val miner: String,
        val merkleRoot: String,
        val prevHash: String,
        val hash: String,
        val nonce: Int,
        val difficulty: Int
    )

    data class Transaction(
        val txId: String,
        val domain: String,
        val ip: String,
        val category: String,
        val riskScore: Double,
        val reportedBy: String,
        val timestamp: Long,
        val signature: String
    )

    fun reportThreat(domain: String, ip: String, category: String, riskScore: Float) {
        val requestBody = TransactionRequest(
            domain = domain,
            ip = ip,
            category = category.lowercase(),
            riskScore = riskScore
        )
        
        val json = gson.toJson(requestBody)
        val body = json.toRequestBody(JSON)
        
        val request = Request.Builder()
            .url("$BASE_URL/tx")
            .post(body)
            .build()

        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                Log.e(TAG, "Failed to report threat: ${e.message}")
            }

            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                if (response.isSuccessful) {
                    Log.d(TAG, "Reported threat: $domain ($ip)")
                    triggerMine()
                } else {
                    Log.w(TAG, "Server error: ${response.code}")
                }
                response.close()
            }
        })
    }

    private fun triggerMine() {
        val request = Request.Builder()
            .url("$BASE_URL/mine")
            .post("{}".toRequestBody(JSON))
            .build()

        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                Log.e(TAG, "Failed to trigger mine: ${e.message}")
            }

            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                response.close()
            }
        })
    }

    fun getStats(onResult: (BlockchainStats?) -> Unit) {
        val request = Request.Builder().url("$BASE_URL/stats").get().build()
        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) { onResult(null) }
            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                if (response.isSuccessful) {
                    try {
                        val stats = gson.fromJson(response.body?.string(), BlockchainStats::class.java)
                        onResult(stats)
                    } catch (e: Exception) { onResult(null) }
                } else { onResult(null) }
                response.close()
            }
        })
    }

    fun getChain(onResult: (List<Block>?) -> Unit) {
        val request = Request.Builder().url("$BASE_URL/chain").get().build()
        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) { onResult(null) }
            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                if (response.isSuccessful) {
                    try {
                        val listType = object : com.google.gson.reflect.TypeToken<List<Block>>() {}.type
                        val chain = gson.fromJson<List<Block>>(response.body?.string(), listType)
                        onResult(chain)
                    } catch (e: Exception) { onResult(null) }
                } else { onResult(null) }
                response.close()
            }
        })
    }
}
