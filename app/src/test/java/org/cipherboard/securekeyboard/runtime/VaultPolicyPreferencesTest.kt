// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import androidx.test.core.app.ApplicationProvider
import org.cipherboard.securestorage.VaultLockPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class VaultPolicyPreferencesTest {
    private val context get() = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Before
    fun clearPreferences() {
        context.getSharedPreferences("cipherboard_public_settings", android.content.Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun defaultsToOneMinute() {
        assertEquals(VaultLockPolicy.ONE_MINUTE, VaultPolicyPreferences.read(context))
    }

    @Test
    fun persistsEverySupportedPolicy() {
        VaultLockPolicy.entries.forEach { policy ->
            assertTrue(VaultPolicyPreferences.write(context, policy))
            assertEquals(policy, VaultPolicyPreferences.read(context))
        }
    }

    @Test
    fun unknownStoredValueFailsClosedToDefault() {
        context.getSharedPreferences("cipherboard_public_settings", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("vault_lock_policy", "UNKNOWN")
            .commit()
        assertEquals(VaultLockPolicy.ONE_MINUTE, VaultPolicyPreferences.read(context))
    }

    @Test
    fun viewerTimeoutDefaultsToOneMinuteAndPersistsSupportedValues() {
        assertEquals(SecureViewerTimeout.ONE_MINUTE, ViewerTimeoutPreferences.read(context))
        SecureViewerTimeout.entries.forEach { timeout ->
            assertTrue(ViewerTimeoutPreferences.write(context, timeout))
            assertEquals(timeout, ViewerTimeoutPreferences.read(context))
        }
    }

    @Test
    fun unknownViewerTimeoutFailsClosedToDefault() {
        context.getSharedPreferences("cipherboard_public_settings", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("secure_viewer_timeout", "UNBOUNDED")
            .commit()
        assertEquals(SecureViewerTimeout.ONE_MINUTE, ViewerTimeoutPreferences.read(context))
    }
}
