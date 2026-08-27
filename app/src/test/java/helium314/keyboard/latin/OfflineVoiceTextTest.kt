// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class OfflineVoiceTextTest {
    @Test
    fun activeRussianLayoutSelectsRussianModel() {
        assertEquals("ru", offlineVoiceModelLanguage(Locale.forLanguageTag("ru-RU")))
        assertEquals("en", offlineVoiceModelLanguage(Locale.forLanguageTag("en-US")))
        assertEquals("en", offlineVoiceModelLanguage(null))
    }

    @Test
    fun voskJsonIsReducedToBoundedSingleLineText() {
        assertEquals("привет мир", parseOfflineVoiceResult("""{"text":"  привет\nмир  "}"""))
        assertNull(parseOfflineVoiceResult("""{"partial":"привет"}"""))
        assertNull(parseOfflineVoiceResult("not json"))
    }

    @Test
    fun finalizedSegmentsAreJoinedWithoutPersistingAudio() {
        assertEquals("hello world", joinOfflineVoiceSegments(listOf("hello", "world")))
    }
}
