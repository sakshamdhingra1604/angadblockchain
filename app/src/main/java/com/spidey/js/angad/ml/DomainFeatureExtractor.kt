package com.spidey.js.angad.ml

import android.net.Uri
import java.util.*
import kotlin.math.ln

object DomainFeatureExtractor {

    private val SUSPICIOUS_TLDS = setOf(
        "xyz", "top", "club", "work", "click", "link", "loan", "win", "bid", "download",
        "racing", "review", "cricket", "party", "gq", "ml", "cf", "tk", "ga", "icu",
        "buzz", "rest", "cyou", "monster", "surf", "pw", "cc", "su", "shop", "online", "site", "live"
    )

    private val MISLEADING_TLDS = setOf(
        "cm", "co", "om", "vip", "info"
    )

    private val KNOWN_BRANDS = listOf(
        "paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix",
        "bankofamerica", "wellsfargo", "chase", "citibank", "americanexpress", "instagram",
        "linkedin", "twitter", "ebay", "dropbox", "adobe", "docusign", "coinbase", "binance",
        "outlook", "office365", "icloud", "steam", "spotify", "metamask", "telegram", "whatsapp"
    )

    private val URL_SHORTENER_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id"
    )

    private val SUSPICIOUS_FILE_EXTENSIONS = setOf(
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jar", "msi", "apk",
        "dmg", "zip", "rar", "7z", "ps1"
    )

    private val LOGIN_KEYWORDS = setOf("login", "signin", "log-in", "sign-in")
    private val SECURE_KEYWORDS = setOf("secure", "security", "protected", "safe")
    private val ACCOUNT_KEYWORDS = setOf("account", "acct", "profile")
    private val UPDATE_KEYWORDS = setOf("update", "renew", "restore")
    private val VERIFY_KEYWORDS = setOf("verify", "verification", "confirm", "validate")
    private val BANK_KEYWORDS = setOf("bank", "banking", "wallet", "billing", "payment")

    private val STRUCTURAL_CHARS = setOf(':', '/', '.', '-', '_', '?', '&', '=', '%', '#', '@', '~', '+')
    private val CONSONANTS = setOf(
        'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z',
        'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z'
    )

    // Cyrillic and Greek unicode ranges used in homoglyph spoofing
    private val HOMOGLYPH_REGEX = Regex("[\\u0400-\\u04FF\\u0370-\\u03FF]")
    private val HEX_ENCODED_REGEX = Regex("%[0-9a-fA-F]{2}")
    private val NESTED_URL_REGEX = Regex("(url|redirect|next|dest|continue)=https?", RegexOption.IGNORE_CASE)

    private val TRUSTED_INFRASTRUCTURE = setOf(
        // Google & Android
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "android.com", "gvt1.com", "ggpht.com", "googlevideo.com", "youtube.com", "ytimg.com",
        "play.google.com", "1e100.net", "app-measurement.com", "google-analytics.com",
        "firebaseio.com", "crashlytics.com",
        // Meta / Facebook / WhatsApp / Instagram
        "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net",
        "meta.com", "facebook.net", "fbsbx.com",
        // Apple
        "apple.com", "icloud.com", "aaplimg.com", "mzstatic.com",
        // Microsoft
        "microsoft.com", "live.com", "office.com", "windows.com", "msn.com", "bing.com", "azure.com", "msftncsi.com",
        // Samsung & Device OEMs
        "samsung.com", "samsungcloud.com", "samsungapps.com", "samsungqbe.com",
        "samsungosp.com", "samsungcloudsolution.com", "samsungdm.com", "samsungpositioning.com",
        // CDNs & Infrastructure
        "cloudflare.com", "cloudfront.net", "akamaihd.net", "akamaized.net", "fastly.net", "edgekey.net",
        // Mobile Analytics & Push
        "adjust.com", "appsflyer.com", "branch.io", "onesignal.com",
        // Popular Verified Apps
        "snapchat.com", "snap.com", "spotify.com", "netflix.com", "amazon.in", "amazon.com", "flipkart.com",
        // Common Essential Services
        "jio.com", "airtel.in", "gov.in", "nic.in", "github.com", "githubusercontent.com"
    )

    fun isBuiltinTrusted(domain: String): Boolean {
        val cleanHost = domain.lowercase().trim().removePrefix("www.")
        return TRUSTED_INFRASTRUCTURE.any { cleanHost == it || cleanHost.endsWith(".$it") }
    }

    val FEATURE_NAMES = listOf(
        "url_length", "num_dots", "num_hyphens", "num_underscores",
        "num_digits", "num_special_chars", "has_at_symbol", "path_segments_count",
        "query_params_count", "has_fragment", "shannon_entropy", "consecutive_consonants",
        "host_length", "num_subdomains", "has_ip_address", "is_shortener",
        "suspicious_tld", "has_punycode", "domain_digit_ratio", "tld_length",
        "is_https", "has_port", "port_is_standard", "double_slash_path",
        "hex_encoded_count", "has_dangerous_ext", "login_keywords", "secure_keywords",
        "account_keywords", "update_keywords", "verify_keywords", "bank_keywords",
        "brand_mismatch", "nested_redirect", "excessive_subdomains", "random_domain_score",
        "long_subdomain_label", "path_ratio", "brand_in_subdomain", "misleading_tld",
        "homoglyph_score"
    )

    /**
     * Extracts exactly the 41 engineered features matching ShieldNet contract.
     * Order and scaling must match ml_engine/feature_extractor.py identically.
     */
    fun extract(rawUrl: String): FloatArray {
        val features = FloatArray(41)
        val fullUrl = if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
            "http://$rawUrl"
        } else {
            rawUrl
        }
        val urlLower = fullUrl.lowercase()

        val uri = try {
            Uri.parse(fullUrl)
        } catch (e: Exception) {
            null
        }

        val scheme = uri?.scheme?.lowercase() ?: (if (fullUrl.startsWith("https://")) "https" else "http")
        val host = (uri?.host ?: extractHostFallback(fullUrl)).lowercase()
        val path = uri?.path ?: ""
        val query = uri?.query ?: ""
        val fragment = uri?.fragment ?: ""

        val (registeredDomain, subdomain, tld) = extractDomainParts(host)
        val subdomainLabels = if (subdomain.isNotEmpty()) subdomain.split('.').filter { it.isNotEmpty() } else emptyList()
        val pathSegments = if (path.isNotEmpty()) path.split('/').filter { it.isNotEmpty() } else emptyList()
        val queryParams = if (query.isNotEmpty()) query.split('&').filter { it.isNotEmpty() } else emptyList()

        val port = uri?.port ?: -1
        val hasPort = port != -1
        val portIsStandard = if (hasPort) (port == 80 || port == 443) else true

        // 0: len(url)
        features[0] = fullUrl.length.toFloat()
        // 1: url.count(".")
        features[1] = fullUrl.count { it == '.' }.toFloat()
        // 2: url.count("-")
        features[2] = fullUrl.count { it == '-' }.toFloat()
        // 3: url.count("_")
        features[3] = fullUrl.count { it == '_' }.toFloat()
        // 4: sum(c.isdigit())
        features[4] = fullUrl.count { it.isDigit() }.toFloat()
        // 5: special chars count (not alnum and not structural)
        features[5] = fullUrl.count { !it.isLetterOrDigit() && it !in STRUCTURAL_CHARS }.toFloat()
        // 6: has '@'
        features[6] = if (fullUrl.contains('@')) 1.0f else 0.0f
        // 7: path_segments length
        features[7] = pathSegments.size.toFloat()
        // 8: query_params length
        features[8] = queryParams.size.toFloat()
        // 9: has fragment
        features[9] = if (fragment.isNotEmpty()) 1.0f else 0.0f
        // 10: shannon entropy of url
        features[10] = calculateEntropy(fullUrl)
        // 11: max consecutive consonants
        features[11] = calculateMaxConsonants(fullUrl).toFloat()
        // 12: len(hostname)
        features[12] = host.length.toFloat()
        // 13: subdomain labels count
        features[13] = subdomainLabels.size.toFloat()
        // 14: is IP address
        features[14] = if (isIpAddress(host)) 1.0f else 0.0f
        // 15: is URL shortener
        features[15] = if (URL_SHORTENER_DOMAINS.any { host == it || host.endsWith(".$it") }) 1.0f else 0.0f
        // 16: suspicious TLD
        features[16] = if (SUSPICIOUS_TLDS.contains(tld)) 1.0f else 0.0f
        // 17: is punycode / "xn--"
        features[17] = if (host.contains("xn--")) 1.0f else 0.0f
        // 18: digit ratio of registered domain
        features[18] = digitRatio(registeredDomain)
        // 19: len(tld)
        features[19] = tld.length.toFloat()
        // 20: is HTTPS
        features[20] = if (scheme == "https") 1.0f else 0.0f
        // 21: has port
        features[21] = if (hasPort) 1.0f else 0.0f
        // 22: port is standard
        features[22] = if (portIsStandard) 1.0f else 0.0f
        // 23: "//" in path
        features[23] = if (path.contains("//")) 1.0f else 0.0f
        // 24: hex-encoded count
        features[24] = HEX_ENCODED_REGEX.findAll(fullUrl).count().toFloat()
        // 25: suspicious file extension in path
        val pathExt = if (path.contains('.')) path.substringAfterLast('.').lowercase() else ""
        features[25] = if (pathExt.isNotEmpty() && SUSPICIOUS_FILE_EXTENSIONS.contains(pathExt)) 1.0f else 0.0f
        // 26: login keywords
        features[26] = if (LOGIN_KEYWORDS.any { urlLower.contains(it) }) 1.0f else 0.0f
        // 27: secure keywords
        features[27] = if (SECURE_KEYWORDS.any { urlLower.contains(it) }) 1.0f else 0.0f
        // 28: account keywords
        features[28] = if (ACCOUNT_KEYWORDS.any { urlLower.contains(it) }) 1.0f else 0.0f
        // 29: update keywords
        features[29] = if (UPDATE_KEYWORDS.any { urlLower.contains(it) }) 1.0f else 0.0f
        // 30: verify keywords
        features[30] = if (VERIFY_KEYWORDS.any { urlLower.contains(it) }) 1.0f else 0.0f
        // 31: bank keywords
        features[31] = if (BANK_KEYWORDS.any { urlLower.contains(it) }) 1.0f else 0.0f
        // 32: brand impersonation score
        features[32] = brandImpersonationScore(urlLower, registeredDomain)
        // 33: nested redirect URL in query
        features[33] = if (NESTED_URL_REGEX.containsMatchIn(query)) 1.0f else 0.0f
        // 34: excessive subdomains (>3)
        features[34] = if (subdomainLabels.size > 3) 1.0f else 0.0f
        // 35: random-looking domain score
        features[35] = randomDomainScore(registeredDomain)
        // 36: any subdomain label > 20 chars
        features[36] = if (subdomainLabels.any { it.length > 20 }) 1.0f else 0.0f
        // 37: path ratio
        features[37] = if (fullUrl.isNotEmpty()) (path.length.toFloat() / fullUrl.length.toFloat()) else 0.0f
        // 38: known brand in subdomain but not registered domain
        features[38] = if (KNOWN_BRANDS.any { subdomain.contains(it) } && registeredDomain !in KNOWN_BRANDS) 1.0f else 0.0f
        // 39: misleading TLD
        features[39] = if (MISLEADING_TLDS.contains(tld)) 1.0f else 0.0f
        // 40: homoglyph score
        features[40] = homoglyphScore(host)

        return features
    }

    /**
     * 65-feature extractor for legacy / CICIDS2017 Model 1 support.
     */
    fun extract65(domain: String, dstPort: Int, isTcp: Boolean): FloatArray {
        val features65 = FloatArray(65)
        val f41 = extract(domain)
        for (i in 0 until 41) {
            features65[i] = f41[i]
        }
        features65[41] = (dstPort.toFloat() / 65535f).coerceIn(0f, 1f)
        features65[42] = if (isTcp) 1.0f else 0.0f
        val cal = Calendar.getInstance()
        features65[43] = cal.get(Calendar.HOUR_OF_DAY).toFloat() / 23f
        features65[44] = if (cal.get(Calendar.DAY_OF_WEEK) in Calendar.MONDAY..Calendar.FRIDAY) 1.0f else 0.0f
        return features65
    }

    fun extract(domain: String, dstPort: Int, isTcp: Boolean): FloatArray {
        return extract65(domain, dstPort, isTcp)
    }

    private fun extractHostFallback(url: String): String {
        var clean = url.substringAfter("://").substringBefore('/').substringBefore('?')
        clean = clean.substringBefore(':')
        return clean
    }

    private data class DomainParts(val domain: String, val subdomain: String, val tld: String)

    private fun extractDomainParts(host: String): DomainParts {
        if (host.isEmpty() || isIpAddress(host)) {
            return DomainParts(host, "", "")
        }
        val parts = host.split('.').filter { it.isNotEmpty() }
        if (parts.size <= 1) {
            return DomainParts(host, "", "")
        }
        // Handle common two-part TLDs (e.g. .co.uk, .com.au, .gov.in)
        val isTwoPartTld = parts.size >= 3 && parts[parts.size - 2].length <= 3 && parts.last().length == 2
        val (domain, tld, subParts) = if (isTwoPartTld && parts.size >= 3) {
            val d = parts[parts.size - 3]
            val t = "${parts[parts.size - 2]}.${parts.last()}"
            val s = parts.dropLast(3)
            Triple(d, t, s)
        } else {
            val d = parts[parts.size - 2]
            val t = parts.last()
            val s = parts.dropLast(2)
            Triple(d, t, s)
        }
        return DomainParts(domain, subParts.joinToString("."), tld)
    }

    private fun isIpAddress(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size == 4) {
            return parts.all { it.toIntOrNull()?.let { num -> num in 0..255 } == true }
        }
        return false
    }

    private fun calculateEntropy(s: String): Float {
        if (s.isEmpty()) return 0f
        val counts = mutableMapOf<Char, Int>()
        for (c in s) counts[c] = (counts[c] ?: 0) + 1
        var entropy = 0.0
        val len = s.length.toDouble()
        for (count in counts.values) {
            val p = count.toDouble() / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy.toFloat()
    }

    private fun calculateMaxConsonants(s: String): Int {
        var best = 0
        var run = 0
        for (c in s) {
            if (c in CONSONANTS) {
                run++
                best = maxOf(best, run)
            } else {
                run = 0
            }
        }
        return best
    }

    private fun digitRatio(s: String): Float {
        if (s.isEmpty()) return 0f
        return s.count { it.isDigit() }.toFloat() / s.length.toFloat()
    }

    private fun brandImpersonationScore(urlLower: String, registeredDomain: String): Float {
        var hits = 0
        for (brand in KNOWN_BRANDS) {
            if (urlLower.contains(brand) && registeredDomain != brand) {
                hits++
            }
        }
        return (hits.toFloat() / 3.0f).coerceAtMost(1.0f)
    }

    private fun randomDomainScore(domainLabel: String): Float {
        if (domainLabel.length < 4) return 0f
        val entropy = calculateEntropy(domainLabel)
        val consonantRun = calculateMaxConsonants(domainLabel)
        val dRatio = digitRatio(domainLabel)
        var score = 0f
        if (entropy > 3.5f) score += 0.4f
        if (consonantRun >= 5) score += 0.3f
        if (dRatio > 0.3f) score += 0.3f
        return score.coerceAtMost(1.0f)
    }

    private fun homoglyphScore(hostname: String): Float {
        val matches = HOMOGLYPH_REGEX.findAll(hostname).count()
        val hasAsciiLetters = hostname.any { it.code in 65..90 || it.code in 97..122 }
        if (matches > 0 && hasAsciiLetters) {
            return (matches.toFloat() / 5.0f).coerceAtMost(1.0f)
        }
        return 0f
    }
}
