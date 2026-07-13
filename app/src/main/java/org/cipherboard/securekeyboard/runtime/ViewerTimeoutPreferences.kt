// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.content.Context

enum class SecureViewerTimeout(val millis: Long) {
    FIFTEEN_SECONDS(15_000L),
    THIRTY_SECONDS(30_000L),
    ONE_MINUTE(60_000L),
    FIVE_MINUTES(5 * 60_000L),
}

/** Stores only a non-secret display policy; app backup remains disabled. */
object ViewerTimeoutPreferences {
    private const val FILE_NAME = "cipherboard_public_settings"
    private const val KEY_TIMEOUT = "secure_viewer_timeout"

    fun read(context: Context): SecureViewerTimeout {
        val stored = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
            .getString(KEY_TIMEOUT, null)
        return SecureViewerTimeout.entries.firstOrNull { it.name == stored }
            ?: SecureViewerTimeout.ONE_MINUTE
    }

    fun write(context: Context, timeout: SecureViewerTimeout): Boolean =
        context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_TIMEOUT, timeout.name)
            .commit()
}
