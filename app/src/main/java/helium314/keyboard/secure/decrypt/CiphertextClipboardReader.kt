// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.content.ClipboardManager
import android.content.Context

/** Reads one explicitly requested, allocation-bounded ciphertext item from the system clipboard. */
internal object CiphertextClipboardReader {
    fun read(context: Context): String? = try {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = clipboard?.primaryClip
        if (clip == null || clip.itemCount != 1) {
            null
        } else {
            CiphertextSelection.copyBoundedUntrustedText(clip.getItemAt(0).text)
        }
    } catch (_: RuntimeException) {
        null
    }
}
