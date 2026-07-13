/*
 * Copyright (C) 2014 The Android Open Source Project
 * modified
 * SPDX-License-Identifier: Apache-2.0 AND GPL-3.0-only
 */

package helium314.keyboard.latin.define

import android.content.Context
import helium314.keyboard.latin.settings.DebugSettings
import helium314.keyboard.latin.settings.Defaults
import helium314.keyboard.latin.utils.prefs

object DebugFlags {
    @JvmField
    var DEBUG_ENABLED = false

    fun init(context: Context) {
        DEBUG_ENABLED = context.prefs().getBoolean(DebugSettings.PREF_DEBUG_MODE, Defaults.PREF_DEBUG_MODE)
    }
}
