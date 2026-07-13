// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.Context
import android.content.res.Configuration
import android.graphics.Color
import android.view.ContextThemeWrapper
import android.view.View
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.RadioButton
import android.widget.Spinner
import android.widget.TextView
import androidx.core.graphics.ColorUtils
import androidx.test.core.app.ApplicationProvider
import helium314.keyboard.latin.R
import kotlin.test.Test
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class PlatformThemeContrastTest {
    @Test
    fun nativeSecureControlsAreLegibleInLightMode() {
        assertNativeControlContrast(Configuration.UI_MODE_NIGHT_NO)
    }

    @Test
    fun nativeSecureControlsAreLegibleInDarkMode() {
        assertNativeControlContrast(Configuration.UI_MODE_NIGHT_YES)
    }

    private fun assertNativeControlContrast(nightMode: Int) {
        val context = themedContext(nightMode)
        val background = context.resolveColor(android.R.attr.colorBackground)
        val primaryControls = listOf(
            "TextView" to TextView(context).currentTextColor,
            "EditText" to EditText(context).currentTextColor,
            "RadioButton" to RadioButton(context).currentTextColor,
            "Spinner item" to spinnerItemTextColor(context),
        )

        primaryControls.forEach { (name, foreground) ->
            assertContrastAtLeast(name, foreground, background, 4.5)
        }

        val hintColor = EditText(context).currentHintTextColor
        assertContrastAtLeast("EditText hint", hintColor, background, 4.5)
    }

    private fun themedContext(nightMode: Int): Context {
        val application = ApplicationProvider.getApplicationContext<Context>()
        val configuration = Configuration(application.resources.configuration).apply {
            uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or nightMode
        }
        return ContextThemeWrapper(
            application.createConfigurationContext(configuration),
            R.style.platformActivityTheme,
        )
    }

    private fun spinnerItemTextColor(context: Context): Int {
        val spinner = Spinner(context)
        val view = ArrayAdapter(
            context,
            android.R.layout.simple_spinner_item,
            listOf("Contact"),
        ).getView(0, null, spinner)
        assertTrue(view is TextView, "Platform spinner item must remain a TextView")
        return view.currentTextColor
    }

    private fun Context.resolveColor(attribute: Int): Int {
        val attributes = obtainStyledAttributes(intArrayOf(attribute))
        return try {
            attributes.getColor(0, Color.TRANSPARENT)
        } finally {
            attributes.recycle()
        }
    }

    private fun assertContrastAtLeast(
        name: String,
        foreground: Int,
        background: Int,
        minimum: Double,
    ) {
        val opaqueBackground = if (Color.alpha(background) == 255) {
            background
        } else {
            ColorUtils.compositeColors(background, Color.WHITE)
        }
        val opaqueForeground = if (Color.alpha(foreground) == 255) {
            foreground
        } else {
            ColorUtils.compositeColors(foreground, opaqueBackground)
        }
        val contrast = ColorUtils.calculateContrast(opaqueForeground, opaqueBackground)
        assertTrue(
            contrast >= minimum,
            "$name contrast $contrast is below $minimum " +
                "(foreground=${colorHex(foreground)}, background=${colorHex(background)})",
        )
    }

    private fun colorHex(color: Int): String = String.format("#%08X", color)
}
