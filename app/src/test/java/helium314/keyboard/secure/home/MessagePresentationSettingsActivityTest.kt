// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.content.ComponentName
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "land")
class MessagePresentationSettingsActivityTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    @Suppress("DEPRECATION")
    fun settingsSurfaceBuildsInLandscapeAndIsNotExported() {
        val controller = Robolectric.buildActivity(MessagePresentationSettingsActivity::class.java)
            .create()
            .start()
            .resume()
        val activity = controller.get()

        assertFalse(activity.isFinishing)
        assertTrue(activity.findViewById<android.view.ViewGroup>(android.R.id.content).childCount > 0)

        val info = context.packageManager.getActivityInfo(
            ComponentName(context, MessagePresentationSettingsActivity::class.java),
            0,
        )
        assertFalse(info.exported)
        controller.pause().stop().destroy()
    }
}
