// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.app.Application
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.Spinner
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class EmbeddedSecureTapjackingTest {
    @Test
    fun `embedded root and every sensitive descendant reject obscured touches`() {
        val context = ApplicationProvider.getApplicationContext<Application>()
        val root = LinearLayout(context)
        val modeGroup = LinearLayout(context)
        val encryptMode = RadioButton(context)
        val decryptMode = RadioButton(context)
        val contactChooser = Spinner(context)
        val encrypt = Button(context)
        val decrypt = Button(context)
        val contextAction = Button(context)
        val clear = ImageButton(context)
        val close = ImageButton(context)
        modeGroup.addView(encryptMode)
        modeGroup.addView(decryptMode)
        root.addView(modeGroup)
        root.addView(contactChooser)
        root.addView(encrypt)
        root.addView(decrypt)
        root.addView(contextAction)
        root.addView(clear)
        root.addView(close)

        protectEmbeddedSecureInteractions(root)

        val protectedViews = listOf<View>(
            root,
            modeGroup,
            encryptMode,
            decryptMode,
            contactChooser,
            encrypt,
            decrypt,
            contextAction,
            clear,
            close,
        )
        val obscuredTouch = obscuredTouch()
        try {
            protectedViews.forEach { view ->
                assertTrue(view.filterTouchesWhenObscured)
                assertFalse(view.onFilterTouchEventForSecurity(obscuredTouch))
            }
        } finally {
            obscuredTouch.recycle()
        }
    }

    private fun obscuredTouch(): MotionEvent {
        val now = SystemClock.uptimeMillis()
        val pointerProperties = arrayOf(MotionEvent.PointerProperties().apply {
            id = 0
            toolType = MotionEvent.TOOL_TYPE_FINGER
        })
        val pointerCoordinates = arrayOf(MotionEvent.PointerCoords().apply {
            x = 1f
            y = 1f
            pressure = 1f
            size = 1f
        })
        return MotionEvent.obtain(
            now,
            now,
            MotionEvent.ACTION_DOWN,
            1,
            pointerProperties,
            pointerCoordinates,
            0,
            0,
            1f,
            1f,
            0,
            0,
            InputDevice.SOURCE_TOUCHSCREEN,
            MotionEvent.FLAG_WINDOW_IS_OBSCURED,
        )
    }
}
