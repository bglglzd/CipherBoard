// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import helium314.keyboard.latin.LatinIME

/** Blocks plaintext editing unless Android is currently routing input through CipherBoard itself. */
internal object SecureComposerImeTrust {
    fun isCipherBoardSelected(context: Context): Boolean {
        val selected = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
        ) ?: return false
        val selectedComponent = ComponentName.unflattenFromString(selected) ?: return false
        return selectedComponent == ComponentName(context, LatinIME::class.java)
    }
}
