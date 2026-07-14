// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.os.Handler
import android.os.Looper
import java.util.UUID

/** Process-local, one-shot handoff for the non-exported IME authentication activity. */
internal object EmbeddedVaultUnlockBridge {
    private data class Session(
        val token: String,
        val callback: (Boolean) -> Unit,
        var activated: Boolean = false,
    )

    private val mainHandler = Handler(Looper.getMainLooper())
    private var session: Session? = null

    @Synchronized
    fun begin(callback: (Boolean) -> Unit): String {
        session = null
        val token = UUID.randomUUID().toString()
        session = Session(token, callback)
        return token
    }

    @Synchronized
    fun activate(token: String): Boolean {
        val current = session ?: return false
        if (current.token != token || current.activated) return false
        current.activated = true
        return true
    }

    fun complete(token: String, unlocked: Boolean) {
        val callback = synchronized(this) {
            val current = session
            if (current?.token != token || !current.activated) return
            session = null
            current.callback
        }
        mainHandler.post { callback(unlocked) }
    }

    @Synchronized
    fun cancel(token: String) {
        if (session?.token == token) session = null
    }
}
