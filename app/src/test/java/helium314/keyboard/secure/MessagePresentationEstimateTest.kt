// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import helium314.keyboard.latin.R
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.TransportPresentation
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MessagePresentationEstimateTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun compactAndWordEstimatesUseTheirOwnUnits() {
        val compact = estimateMessagePresentation(100, TransportPresentation.COMPACT)
        val russian = estimateMessagePresentation(100, TransportPresentation.RUSSIAN_WORDS)
        val english = estimateMessagePresentation(100, TransportPresentation.ENGLISH_WORDS)

        assertEquals(MessagePresentationEstimateUnit.ENCRYPTED_CHARACTERS, compact.unit)
        assertEquals(MessagePresentationEstimateUnit.ENCODED_WORDS, russian.unit)
        assertEquals(MessagePresentationEstimateUnit.ENCODED_WORDS, english.unit)
        assertEquals(russian.value, english.value)
        assertTrue(compact.value > 100)
        assertTrue(russian.value > 0)
    }

    @Test
    fun emptyDraftHasZeroEstimateInEveryPresentation() {
        TransportPresentation.entries.forEach { presentation ->
            assertEquals(0, estimateMessagePresentation(0, presentation).value)
        }
    }

    @Test
    fun wordLimitLeavesRoomForPresentationWrapper() {
        assertEquals(
            CipherBoardCrypto.MAX_PLAINTEXT_BYTES,
            maximumPlaintextBytes(TransportPresentation.COMPACT),
        )
        assertTrue(
            maximumPlaintextBytes(TransportPresentation.RUSSIAN_WORDS) <
                CipherBoardCrypto.MAX_PLAINTEXT_BYTES,
        )
        assertEquals(
            maximumPlaintextBytes(TransportPresentation.RUSSIAN_WORDS),
            maximumPlaintextBytes(TransportPresentation.ENGLISH_WORDS),
        )
    }

    @Test
    fun englishAndRussianUiExplainWordFormatHonestly() {
        val english = context.forLocale(Locale.ENGLISH)
        val russian = context.forLocale(Locale.forLanguageTag("ru"))

        assertTrue(english.getString(R.string.cipherboard_message_format_title).contains("format"))
        assertTrue(english.getString(R.string.cipherboard_message_format_warning).contains("do not hide"))
        assertTrue(english.getString(R.string.cipherboard_message_format_warning).contains("0.4 or newer"))
        assertFalse(english.getString(R.string.cipherboard_message_format_warning).contains("SMS"))

        assertTrue(russian.getString(R.string.cipherboard_message_format_title).contains("сообщения"))
        assertTrue(russian.getString(R.string.cipherboard_message_format_russian).contains("Русские"))
        assertTrue(russian.getString(R.string.cipherboard_message_format_warning).contains("не скрывают"))
        assertTrue(russian.getString(R.string.cipherboard_message_format_warning).contains("0.4 или новее"))
        assertFalse(russian.getString(R.string.cipherboard_message_format_warning).contains("SMS"))
    }

    @Test
    fun everyMessageFormatStringHasACompleteRussianTranslation() {
        val english = context.forLocale(Locale.ENGLISH)
        val russian = context.forLocale(Locale.forLanguageTag("ru"))
        val resources = listOf(
            R.string.cipherboard_message_format_title,
            R.string.cipherboard_message_format_description,
            R.string.cipherboard_message_format_compact,
            R.string.cipherboard_message_format_compact_description,
            R.string.cipherboard_message_format_russian,
            R.string.cipherboard_message_format_russian_description,
            R.string.cipherboard_message_format_english,
            R.string.cipherboard_message_format_english_description,
            R.string.cipherboard_message_format_warning,
            R.string.cipherboard_message_format_save_failed,
        )

        resources.forEach { resource ->
            val englishText = english.getString(resource)
            val russianText = russian.getString(resource)
            assertTrue(englishText.isNotBlank())
            assertTrue(russianText.isNotBlank())
            assertFalse(englishText == russianText, "Missing Russian translation for resource $resource")
        }
    }

    @Test
    fun localizedEstimateNamesTheSelectedRepresentationUnit() {
        val english = context.forLocale(Locale.ENGLISH)
        val russian = context.forLocale(Locale.forLanguageTag("ru"))

        assertTrue(
            english.messagePresentationEstimateText(12, 24, TransportPresentation.ENGLISH_WORDS)
                .contains("encoded words"),
        )
        assertTrue(
            russian.messagePresentationEstimateText(12, 24, TransportPresentation.RUSSIAN_WORDS)
                .contains("кодовых слов"),
        )
    }

    @Test
    fun characterCountUsesEnglishAndRussianPluralRules() {
        val english = context.forLocale(Locale.ENGLISH)
        val russian = context.forLocale(Locale.forLanguageTag("ru"))
        val counts = listOf(1, 2, 5, 21)

        assertEquals(
            listOf("1 character", "2 characters", "5 characters", "21 characters"),
            counts.map { count -> english.localizedCharacterCount(count) },
        )
        assertEquals(
            listOf("1 символ", "2 символа", "5 символов", "21 символ"),
            counts.map { count -> russian.localizedCharacterCount(count) },
        )
    }

    private fun Context.localizedCharacterCount(count: Int): String =
        messagePresentationEstimateText(count, 24, TransportPresentation.COMPACT)
            .substringBefore(" · ")

    private fun Context.forLocale(locale: Locale): Context {
        val configuration = Configuration(resources.configuration)
        configuration.setLocale(locale)
        return createConfigurationContext(configuration)
    }
}
