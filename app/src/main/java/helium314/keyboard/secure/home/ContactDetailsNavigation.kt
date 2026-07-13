// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.os.SystemClock
import android.util.Base64
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Keeps contact identifiers inside this process. Activities exchange only a short-lived random
 * navigation token, so Android task state and Intent inspection do not expose a Vault record key.
 */
internal object ContactDetailsNavigation {
    private const val TOKEN_BYTES = 24
    private const val MAX_ENTRIES = 64
    private const val TOKEN_LIFETIME_MILLIS = 10 * 60 * 1_000L

    private val random = SecureRandom()
    private val entries = ConcurrentHashMap<String, Entry>()

    fun issue(contactId: ByteArray): String {
        require(contactId.isNotEmpty())
        purgeExpired()
        while (entries.size >= MAX_ENTRIES) {
            val oldest = entries.entries.minByOrNull { it.value.createdAtElapsedMillis } ?: break
            release(oldest.key)
        }
        while (true) {
            val tokenBytes = ByteArray(TOKEN_BYTES).also(random::nextBytes)
            val token = try {
                Base64.encodeToString(tokenBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            } finally {
                tokenBytes.fill(0)
            }
            val candidate = Entry(contactId.copyOf(), SystemClock.elapsedRealtime())
            val previous = entries.putIfAbsent(token, candidate)
            if (previous == null) return token
            candidate.contactId.fill(0)
        }
    }

    fun resolve(token: String): ByteArray? {
        if (token.length !in 16..128) return null
        val entry = entries[token] ?: return null
        if (isExpired(entry)) {
            release(token)
            return null
        }
        return entry.contactId.copyOf()
    }

    fun release(token: String?) {
        if (token == null) return
        entries.remove(token)?.contactId?.fill(0)
    }

    private fun purgeExpired() {
        entries.forEach { (token, entry) ->
            if (isExpired(entry)) release(token)
        }
    }

    private fun isExpired(entry: Entry): Boolean =
        SystemClock.elapsedRealtime() - entry.createdAtElapsedMillis > TOKEN_LIFETIME_MILLIS

    private class Entry(
        val contactId: ByteArray,
        val createdAtElapsedMillis: Long,
    )
}
