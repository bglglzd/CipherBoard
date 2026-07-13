// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.text.SpannableStringBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class Utf8ByteLimitFilterTest {
    @Test
    fun enforcesUtf8BytesWithoutSplittingOrAllocatingEncodedCopies() {
        var rejected = false
        val filter = Utf8ByteLimitFilter({ 4 }) { rejected = true }
        val empty = SpannableStringBuilder()

        assertNull(filter.filter("😀", 0, 2, empty, 0, 0))
        val existing = SpannableStringBuilder("😀")
        assertEquals("", filter.filter("a", 0, 1, existing, 2, 2).toString())
        assertTrue(rejected)
    }

    @Test
    fun selectedTransportCanTightenLimitWithoutMutatingExistingText() {
        var limit = 8
        val filter = Utf8ByteLimitFilter({ limit })
        val existing = SpannableStringBuilder("123456")

        assertNull(filter.filter("7", 0, 1, existing, 6, 6))
        limit = 6
        assertEquals("", filter.filter("7", 0, 1, existing, 6, 6).toString())
        assertEquals("123456", existing.toString())
    }
}
