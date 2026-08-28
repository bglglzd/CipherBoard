// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import java.util.Locale
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private const val MAX_TRANSCRIPT_CHARS = 20_000

internal fun offlineVoiceModelLanguage(locale: Locale?): String =
    if (locale?.language.equals("ru", ignoreCase = true)) "ru" else "en"

internal fun parseOfflineVoiceResult(json: String?): String? {
    return parseOfflineVoiceField(json, "text")
}

internal fun parseOfflineVoicePartialResult(json: String?): String? {
    return parseOfflineVoiceField(json, "partial")
}

private fun parseOfflineVoiceField(json: String?, field: String): String? {
    if (json.isNullOrBlank()) return null
    val text = runCatching {
        Json.parseToJsonElement(json).jsonObject[field]?.jsonPrimitive?.contentOrNull
    }.getOrNull() ?: return null
    return text.replace(Regex("\\s+"), " ").trim().take(MAX_TRANSCRIPT_CHARS).ifEmpty { null }
}

internal fun joinOfflineVoiceSegments(segments: List<String>): String =
    segments.joinToString(" ").replace(Regex("\\s+"), " ").trim().take(MAX_TRANSCRIPT_CHARS)
