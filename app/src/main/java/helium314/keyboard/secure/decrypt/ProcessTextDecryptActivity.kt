// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.content.Intent

/** Exported only for Android's selected-text action; it never returns replacement text. */
class ProcessTextDecryptActivity : SecureMessageViewerActivity() {
    override val requiresExplicitDecryptConfirmation: Boolean = true

    override fun readCiphertext(sourceIntent: Intent): String? {
        if (sourceIntent.action != Intent.ACTION_PROCESS_TEXT || sourceIntent.type != "text/plain") {
            return null
        }
        return CiphertextSelection.readBoundedTextExtra(sourceIntent, Intent.EXTRA_PROCESS_TEXT)
    }

    override fun clearCiphertextExtra(sourceIntent: Intent) {
        sourceIntent.removeExtra(Intent.EXTRA_PROCESS_TEXT)
        sourceIntent.removeExtra(Intent.EXTRA_PROCESS_TEXT_READONLY)
    }
}
