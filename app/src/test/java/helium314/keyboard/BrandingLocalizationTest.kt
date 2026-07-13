// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard

import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import helium314.keyboard.latin.BuildConfig
import helium314.keyboard.latin.R
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BrandingLocalizationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun englishBrandingUsesCipherBoard() {
        val localized = context.forLocale(Locale.ENGLISH)

        assertEquals("CipherBoard", localized.getString(R.string.english_ime_name))
        assertEquals("CipherBoard Settings", localized.getString(R.string.ime_settings))
        assertEquals("CipherBoard Spell Checker", localized.getString(R.string.spell_checker_service_name))
        assertEquals(
            "CipherBoard Spell Checker Settings",
            localized.getString(R.string.android_spell_checker_settings),
        )
    }

    @Test
    fun russianBrandingHasTheSameProductIdentity() {
        val localized = context.forLocale(Locale.forLanguageTag("ru"))
        val strings = listOf(
            localized.getString(R.string.english_ime_name),
            localized.getString(R.string.ime_settings),
            localized.getString(R.string.spell_checker_service_name),
            localized.getString(R.string.android_spell_checker_settings),
        )

        assertEquals(BuildConfig.PRODUCT_NAME, strings.first())
        strings.forEach {
            assertFalse(it.contains("HeliBoard", ignoreCase = true), it)
            assertEquals(true, it.contains(BuildConfig.PRODUCT_NAME), it)
        }
    }

    private fun Context.forLocale(locale: Locale): Context {
        val configuration = Configuration(resources.configuration)
        configuration.setLocale(locale)
        return createConfigurationContext(configuration)
    }
}
