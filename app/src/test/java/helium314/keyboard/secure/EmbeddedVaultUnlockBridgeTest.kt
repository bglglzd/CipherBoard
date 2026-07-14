// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.app.Application
import android.content.ComponentName
import android.content.pm.ActivityInfo
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class EmbeddedVaultUnlockBridgeTest {
    @Test
    fun `legacy system credential handoff is not mistaken for Home`() {
        assertTrue(SecureVaultUnlockLifecyclePolicy.cancelOnUserLeave(legacyCredentialPromptPending = false))
        assertFalse(SecureVaultUnlockLifecyclePolicy.cancelOnUserLeave(legacyCredentialPromptPending = true))
    }

    @Test
    fun `unlock host remains alive while legacy credential activity is in front`() {
        val context = ApplicationProvider.getApplicationContext<Application>()
        val info = context.packageManager.getActivityInfo(
            ComponentName(context, SecureVaultUnlockActivity::class.java),
            0,
        )

        assertEquals(0, info.flags and ActivityInfo.FLAG_NO_HISTORY)
        assertFalse(info.exported)
    }

    @Test
    fun `unlock handoff is activated and completed exactly once`() {
        val results = mutableListOf<Boolean>()
        val token = EmbeddedVaultUnlockBridge.begin(results::add)

        assertTrue(EmbeddedVaultUnlockBridge.activate(token))
        assertFalse(EmbeddedVaultUnlockBridge.activate(token))

        EmbeddedVaultUnlockBridge.complete(token, unlocked = true)
        EmbeddedVaultUnlockBridge.complete(token, unlocked = false)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(listOf(true), results)
    }

    @Test
    fun `cancelled unlock handoff cannot be activated or completed`() {
        val results = mutableListOf<Boolean>()
        val token = EmbeddedVaultUnlockBridge.begin(results::add)

        EmbeddedVaultUnlockBridge.cancel(token)
        assertFalse(EmbeddedVaultUnlockBridge.activate(token))
        EmbeddedVaultUnlockBridge.complete(token, unlocked = true)
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(results.isEmpty())
    }
}
