// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.app.Activity
import android.app.Application
import android.content.ComponentCallbacks2
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class SecureRuntimeLifecycleTest {
    @Test
    fun `visible secure IME prevents activity and UI-hidden background deadlines`() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val target = RecordingLifecycleTarget(isSecureImeForeground = true)
        val lifecycle = SecureRuntimeLifecycle(application, target)
        val activity = Robolectric.buildActivity(Activity::class.java).create().start().get()

        lifecycle.onActivityStarted(activity)
        lifecycle.onActivityStopped(activity)
        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN)

        assertEquals(0, target.backgroundCount)

        target.isSecureImeForeground = false
        lifecycle.onActivityStarted(activity)
        lifecycle.onActivityStopped(activity)
        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN)

        assertEquals(2, target.backgroundCount)
    }

    private class RecordingLifecycleTarget(
        override var isSecureImeForeground: Boolean,
    ) : SecureRuntimeLifecycleTarget {
        var backgroundCount = 0

        override fun lockVault() = Unit
        override fun onBackgrounded() {
            backgroundCount++
        }
        override fun onForegrounded(): Boolean = true
        override fun lockIfExpired(): Boolean = false
    }
}
