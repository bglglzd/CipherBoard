// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.content.Context
import org.cipherboard.securestorage.VaultLockPolicy

/** Stores only the non-secret lock timeout selection; all app data remains excluded from backup. */
object VaultPolicyPreferences {
    private const val FILE_NAME = "cipherboard_public_settings"
    private const val KEY_POLICY = "vault_lock_policy"

    fun read(context: Context): VaultLockPolicy {
        val stored = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
            .getString(KEY_POLICY, null)
        return VaultLockPolicy.entries.firstOrNull { it.name == stored } ?: VaultLockPolicy.ONE_MINUTE
    }

    fun write(context: Context, policy: VaultLockPolicy): Boolean =
        context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_POLICY, policy.name)
            .commit()
}
