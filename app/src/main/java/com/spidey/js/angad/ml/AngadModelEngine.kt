package com.spidey.js.angad.ml

import android.content.Context
import android.util.Log
import android.util.LruCache
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

class AngadModelEngine(private val context: Context) {

    private var interpreter1: Interpreter? = null  // Network Flow Classifier (CICIDS2017)
    private var interpreter2: Interpreter? = null  // URL/Domain Threat Classifier (ShieldNet)
    private var interpreter3: Interpreter? = null  // DNS Payload Byte Classifier (PayloadNet)
    private val cache = LruCache<String, ModelVerdict>(500)

    companion object {
        private const val TAG = "AngadModelEngine"
        // MODEL 1: Network intrusion / flow baseline (CICIDS-2017 — 65 packet features)
        // Used to detect: DDoS, Botnet, PortScan, Web Attacks on live connections
        private const val MODEL1_PATH = "ml/deep_classifier_cicids2017.tflite"
        // MODEL 2: ShieldNet — URL + Domain Phishing/Scam AI (41 URL features + char-level CNN)
        // Used to detect: Phishing, Malware, Data Leak, Scam from domain names
        // NOTE: cicids2018 and unsw models are NOT loaded — same task as cicids2017, wastes RAM
        private const val MODEL2_PATH = "ml/shieldnet_quantized_dynamic.tflite"
        private const val MODEL2_FALLBACK_PATH = "ml/shieldnet.tflite"
        // MODEL 3: Payload Byte Classifier — built by team, takes DNS query raw bytes
        // Input: [1, 266] = causal byte features (log length, entropy, printable, zeros, 6 structural, 256 histogram)
        // Output: [1, 1] = 0.0 (safe) / 1.0 (malicious DNS pattern)
        // Catches: DNS tunneling, C2 beaconing, DGA via DNS query bytes
        private const val MODEL3_PATH = "ml/deep_classifier_payload.tflite"
        private const val MODEL3_INPUT_SIZE = 266
        
        const val SAFE_THRESHOLD = 0.25f
        const val WARN_THRESHOLD = 0.35f
        const val BLOCK_THRESHOLD = 0.55f
    }

    data class ModelVerdict(
        val score: Float,
        val classification: String,
        val reasons: List<String> = emptyList(),
        val featureHighlights: Map<String, Float> = emptyMap(),
        val model1Score: Float = 0f,
        val model2Score: Float = 0f,
        val model3Score: Float = 0f  // Payload classifier score
    )

    init {
        try {
            val model1 = loadModelFile(MODEL1_PATH)
            val options = Interpreter.Options().apply {
                setNumThreads(1) // Better for stability in VpnService
                setUseXNNPACK(true)
            }
            interpreter1 = Interpreter(model1, options)
            interpreter1?.allocateTensors()
            Log.d(TAG, "Primary Model Loaded: $MODEL1_PATH")

            try {
                val model2 = try {
                    loadModelFile(MODEL2_PATH)
                } catch (e: Exception) {
                    Log.w(TAG, "Could not load $MODEL2_PATH, falling back to $MODEL2_FALLBACK_PATH", e)
                    loadModelFile(MODEL2_FALLBACK_PATH)
                }
                interpreter2 = Interpreter(model2, options)
                interpreter2?.allocateTensors()
                Log.d(TAG, "ShieldNet Ensemble Model Loaded successfully")
            } catch (e: Exception) {
                Log.w(TAG, "ShieldNet ensemble model failed to load", e)
            }

            // Model 3: DNS Payload Byte Classifier — friend's custom model
            // Analyzes raw byte patterns in DNS queries for tunneling/C2/DGA detection
            try {
                val model3 = loadModelFile(MODEL3_PATH)
                interpreter3 = Interpreter(model3, options)
                interpreter3?.allocateTensors()
                Log.d(TAG, "PayloadNet (DNS Byte Classifier) Loaded: $MODEL3_PATH")
            } catch (e: Exception) {
                Log.w(TAG, "PayloadNet model failed to load — payload analysis disabled", e)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error loading models", e)
        }
    }

    private fun loadModelFile(path: String): MappedByteBuffer {
        val fileDescriptor = context.assets.openFd(path)
        val inputStream = FileInputStream(fileDescriptor.fileDescriptor)
        val fileChannel = inputStream.channel
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, fileDescriptor.startOffset, fileDescriptor.declaredLength)
    }

    @Synchronized
    fun predict(domain: String, dstPort: Int, isTcp: Boolean, rawDnsBytes: ByteArray? = null): ModelVerdict {
        cache.get(domain)?.let { return it }

        val f41 = DomainFeatureExtractor.extract(domain)
        val highlights = mutableMapOf<String, Float>()
        DomainFeatureExtractor.FEATURE_NAMES.forEachIndexed { index, name ->
            if (index < f41.size) {
                highlights[name] = f41[index]
            }
        }

        // Fast-path: Trusted Infrastructure Domains (WhatsApp, Meta, Google, Apple, etc.)
        if (DomainFeatureExtractor.isBuiltinTrusted(domain)) {
            val safeVerdict = ModelVerdict(
                score = 0.00f,
                classification = "Safe",
                reasons = listOf("Verified Infrastructure Domain"),
                featureHighlights = highlights,
                model1Score = 0.00f,
                model2Score = 0.00f,
                model3Score = 0.00f
            )
            cache.put(domain, safeVerdict)
            return safeVerdict
        }

        val startTime = System.currentTimeMillis()
        val f65 = DomainFeatureExtractor.extract65(domain, dstPort, isTcp)
        Log.d(TAG, "Features for $domain: ${f41.take(10).joinToString(", ")}...")
        
        return try {
            // Primary Inference: Model 1 (CICIDS2017 65 features)
            var score1 = 0f
            var primaryClassification = "Safe"
            val classNames1 = listOf("Safe", "Botnet", "DDoS", "DoS", "Infiltration", "PortScan", "Web Attack", "Brute Force", "Heartbleed")
            
            interpreter1?.let { i1 ->
                try {
                    val input1 = prepareInput(i1, f65)
                    val outputShape1 = i1.getOutputTensor(0).shape()
                    val output1 = Array(1) { FloatArray(outputShape1[1]) }
                    i1.run(input1, output1)
                    
                    if (outputShape1[1] > 1) {
                        val maxIndex = output1[0].indices.maxByOrNull { output1[0][it] } ?: 0
                        primaryClassification = classNames1.getOrElse(maxIndex) { "Threat" }
                        score1 = 1.0f - output1[0][0].coerceIn(0f, 1f)
                    } else {
                        score1 = output1[0][0]
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Model 1 execution error", e)
                }
            }

            // Domain Heuristic score (ensures network baseline doesn't stay 0 on obvious malicious patterns)
            val heuristicScore = (
                (if (f41[16] > 0.5f) 0.35f else 0.0f) + // Risky TLD
                (((f41[26] + f41[28] + f41[30] + f41[31]).coerceAtMost(1f)) * 0.40f) + // Phishing keywords
                (if (f41[32] > 0.3f || f41[38] > 0.5f) 0.35f else 0.0f) + // Brand mismatch / spoofing
                (if (f41[17] > 0.5f || f41[40] > 0.0f) 0.40f else 0.0f) + // Punycode / Homograph
                (if (f41[10] > 3.8f) 0.20f else 0.0f)  // High entropy
            ).coerceIn(0f, 1f)
            val effectiveScore1 = maxOf(score1, heuristicScore)

            // ShieldNet Inference: Model 2 (url_input: [1, 200] INT32, feature_input: [1, 41] FLOAT32)
            var score2 = 0f
            var shieldNetClass = "Safe"
            val shieldNetClasses = listOf("Safe", "Phishing", "Malware", "Data Leak", "Scam")

            interpreter2?.let { i2 ->
                try {
                    val urlInput = encodeUrl(domain, 200)
                    val featureInput = arrayOf(f41)
                    val inputCount = i2.inputTensorCount
                    
                    val inputs = if (inputCount >= 2) {
                        val tensor0 = i2.getInputTensor(0)
                        if (tensor0.dataType() == org.tensorflow.lite.DataType.INT32) {
                            arrayOf<Any>(urlInput, featureInput)
                        } else {
                            arrayOf<Any>(featureInput, urlInput)
                        }
                    } else {
                        arrayOf<Any>(featureInput)
                    }

                    val outputProbs = Array(1) { FloatArray(5) }
                    val outputs = mutableMapOf<Int, Any>(0 to outputProbs)
                    i2.runForMultipleInputsOutputs(inputs, outputs)

                    val pSafe = outputProbs[0][0].coerceIn(0f, 1f)
                    score2 = (1.0f - pSafe).coerceIn(0f, 1f)
                    val maxShieldIdx = outputProbs[0].indices.maxByOrNull { outputProbs[0][it] } ?: 0
                    shieldNetClass = shieldNetClasses.getOrElse(maxShieldIdx) { "Threat" }
                    
                    Log.d(TAG, "ShieldNet Raw Outputs: ${outputProbs[0].joinToString(", ")} -> Class: $shieldNetClass, Score: $score2")
                } catch (e: Exception) {
                    Log.w(TAG, "ShieldNet execution error", e)
                }
            }

            // Model 3: Payload Byte Classifier (friend's custom model)
            // Extracts 262 features from raw DNS query bytes:
            //   - 256 features: frequency count of each byte value (0-255) normalized
            //   - 6 features: total length, entropy, printable ratio, max run, unique bytes, null ratio
            var score3 = 0f
            interpreter3?.let { i3 ->
                try {
                    val payloadBytes = rawDnsBytes ?: domain.toByteArray(Charsets.UTF_8)
                    val payloadFeatures = extractPayloadFeatures(payloadBytes)
                    val inputPayload = arrayOf(payloadFeatures)
                    val outputPayload = Array(1) { FloatArray(1) }
                    i3.run(inputPayload, outputPayload)
                    score3 = outputPayload[0][0].coerceIn(0f, 1f)
                    Log.d(TAG, "PayloadNet score for $domain: $score3")
                } catch (e: Exception) {
                    Log.w(TAG, "PayloadNet execution error", e)
                }
            }

            // 3-Model Ensemble Blending
            // ShieldNet (URL/phishing AI) is primary authority
            // PayloadNet (DNS byte patterns) adds extra confidence for DGA/tunneling
            val blendedBase = if (score2 > 0.40f) {
                // ShieldNet dominant: don't let weak models dilute it
                maxOf(score2, (effectiveScore1 * 0.25f + score2 * 0.65f + score3 * 0.10f)).coerceIn(0f, 1f)
            } else {
                // Normal blend: ShieldNet 55%, M1 heuristic 30%, Payload 15%
                (effectiveScore1 * 0.30f + score2 * 0.55f + score3 * 0.15f).coerceIn(0f, 1f)
            }
            val finalScore = blendedBase

            val classification = when {
                finalScore >= BLOCK_THRESHOLD -> {
                    if (shieldNetClass != "Safe") shieldNetClass
                    else if (primaryClassification != "Safe") primaryClassification
                    else "Phishing Threat"
                }
                finalScore >= WARN_THRESHOLD -> "Suspicious"
                else -> "Safe"
            }

            val reasons = mutableListOf<String>()
            if (f41[10] > 3.8f) reasons.add("DGA Pattern Detected (High Entropy)")
            if (f41[16] > 0.5f) reasons.add("Risky TLD Profile (.tk, .xyz, etc)")
            if (f41[26] > 0.5f || f41[28] > 0.5f || f41[30] > 0.5f || f41[31] > 0.5f) reasons.add("Deceptive / Phishing Keywords Found")
            if (f41[32] > 0.3f || f41[38] > 0.5f) reasons.add("Brand Impersonation / Mismatch Detected")
            if (f41[34] > 0.5f) reasons.add("Excessive Subdomains Detected")
            if (f41[14] > 0.5f) reasons.add("Raw IP Address Host (No Domain)")
            if (f41[17] > 0.5f || f41[40] > 0.0f) reasons.add("Punycode / Homograph Threat Detected")
            if (f41[25] > 0.5f) reasons.add("Dangerous / Suspicious File Extension")
            if (score2 > 0.5f && shieldNetClass != "Safe") reasons.add("ShieldNet AI: $shieldNetClass Threat")
            if (score3 > 0.6f) reasons.add("Suspicious DNS Payload Byte Pattern (PayloadNet)")
            if (finalScore >= BLOCK_THRESHOLD && reasons.isEmpty()) reasons.add("Tri-Model Consensus Threat")

            val highlights = mutableMapOf<String, Float>()
            DomainFeatureExtractor.FEATURE_NAMES.forEachIndexed { index, name ->
                if (index < f41.size) {
                    highlights[name] = f41[index]
                }
            }

            val verdict = ModelVerdict(finalScore, classification, reasons, highlights, effectiveScore1, score2, score3)
            cache.put(domain, verdict)

            Log.d(TAG, "Inference for $domain: m1=$effectiveScore1, m2=$score2, m3=$score3, final=$finalScore, time=${System.currentTimeMillis() - startTime}ms")
            verdict
        } catch (e: Exception) {
            Log.e(TAG, "Inference error for $domain: ${e.message}")
            ModelVerdict(0.0f, "Error")
        }
    }

    private fun encodeUrl(url: String, maxLength: Int = 200): Array<IntArray> {
        val encoded = IntArray(maxLength) { 0 } // 0 = PAD
        val trimmed = url.take(maxLength)
        for (i in trimmed.indices) {
            val code = trimmed[i].code
            encoded[i] = if (code in 32..126) {
                code - 32 + 2
            } else {
                1 // 1 = UNK
            }
        }
        return arrayOf(encoded)
    }

    private fun prepareInput(interpreter: Interpreter, features: FloatArray): Any {
        val inputTensor = interpreter.getInputTensor(0)
        val inputType = inputTensor.dataType()
        val shape = inputTensor.shape()
        val expectedSize = shape.last()
        
        return if (inputType == org.tensorflow.lite.DataType.INT32) {
            val intFeatures = IntArray(expectedSize) { i -> 
                if (i < features.size) (features[i] * 100).toInt() else 0 
            }
            arrayOf(intFeatures)
        } else {
            val floatFeatures = FloatArray(expectedSize) { i ->
                if (i < features.size) features[i] else 0f
            }
            arrayOf(floatFeatures)
        }
    }

    /**
     * Extracts 266 normalized causal features from raw DNS/domain bytes for PayloadNet classifier.
     * Matches netguard/payload_model.py schema (format: netguard-initial-payload-v2).
     */
    private fun extractPayloadFeatures(bytes: ByteArray): FloatArray {
        val features = FloatArray(MODEL3_INPUT_SIZE) { 0f }
        if (bytes.isEmpty()) return features

        val sample = if (bytes.size > 512) bytes.copyOfRange(0, 512) else bytes
        val total = sample.size.toFloat().coerceAtLeast(1f)

        // byte counts (0..255)
        val counts = IntArray(256)
        for (b in sample) counts[b.toInt() and 0xFF]++

        // 0: log1p(sample.size)
        features[0] = kotlin.math.ln(1.0 + sample.size).toFloat()

        // 1: Shannon entropy
        var entropy = 0.0
        for (i in 0..255) {
            if (counts[i] > 0) {
                val p = counts[i].toDouble() / total.toDouble()
                entropy -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
            }
        }
        features[1] = entropy.toFloat()

        // 2: printable ratio (bytes 32..126)
        val printable = sample.count { it.toInt() in 32..126 }
        features[2] = printable.toFloat() / total

        // 3: zeros ratio (byte 0x00)
        features[3] = counts[0].toFloat() / total

        // 4..9: structural features
        val isTls = sample.size >= 2 && sample[0] == 0x16.toByte() && sample[1] == 0x03.toByte()
        features[4] = if (isTls) 1f else 0f

        val httpPrefixes = listOf("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ")
        val sampleStr = sample.take(16).toByteArray().toString(Charsets.ISO_8859_1)
        val isHttp = httpPrefixes.any { sampleStr.startsWith(it) }
        features[5] = if (isHttp) 1f else 0f

        val checkLen = minOf(sample.size, 128)
        var hasCrlf = false
        for (i in 0 until checkLen - 1) {
            if (sample[i] == '\r'.code.toByte() && sample[i + 1] == '\n'.code.toByte()) {
                hasCrlf = true
                break
            }
        }
        features[6] = if (hasCrlf) 1f else 0f

        val control = sample.count { 
            val v = it.toInt() and 0xFF
            v < 32 && v != 9 && v != 10 && v != 13 
        }
        features[7] = control.toFloat() / total

        features[8] = counts[32].toFloat() / total // space ratio
        features[9] = (sample[0].toInt() and 0xFF).toFloat() / 255f // first byte value

        // 10..265: byte frequency histogram (256 values)
        for (i in 0..255) {
            features[10 + i] = counts[i].toFloat() / total
        }

        return features
    }

    fun close() {
        interpreter1?.close()
        interpreter2?.close()
        interpreter3?.close()
    }
}
