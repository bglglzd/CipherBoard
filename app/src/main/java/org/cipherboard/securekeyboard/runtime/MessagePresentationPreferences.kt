// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.content.Context
import org.cipherboard.cryptocore.TransportPresentation

/** Stores only the non-secret appearance selected for outgoing ciphertext. */
object MessagePresentationPreferences {
    private const val FILE_NAME = "cipherboard_public_settings"
    private const val KEY_PRESENTATION = "message_transport_presentation"

    fun read(context: Context): TransportPresentation {
        val stored = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
            .getString(KEY_PRESENTATION, null)
        return TransportPresentation.entries.firstOrNull { it.name == stored }
            ?: TransportPresentation.COMPACT
    }

    fun write(context: Context, presentation: TransportPresentation): Boolean =
        context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PRESENTATION, presentation.name)
            .commit()
}
