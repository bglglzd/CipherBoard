// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.event

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SecureTextBuffersTest {
    @Test
    fun stringBuilderOverwriteClearsLengthAndBackingCapacity() {
        val buffer = StringBuilder("plaintext-sentinel")
        assertTrue(buffer.capacity() >= buffer.length)

        buffer.overwriteAndClear()

        assertEquals(0, buffer.length)
        assertEquals(0, buffer.capacity())
    }

    @Test
    fun secureCombinerResetDropsCombinedAndDeadKeyBuffers() {
        val chain = CombinerChain("plaintext-sentinel", "")
        val combinedField = CombinerChain::class.java.getDeclaredField("mCombinedText").apply {
            isAccessible = true
        }
        val combinersField = CombinerChain::class.java.getDeclaredField("mCombiners").apply {
            isAccessible = true
        }

        chain.resetSecurely()

        val combined = combinedField.get(chain) as StringBuilder
        assertEquals(0, combined.length)
        assertEquals(0, combined.capacity())
        @Suppress("UNCHECKED_CAST")
        val deadKeys = (combinersField.get(chain) as List<Combiner>)
            .filterIsInstance<DeadKeyCombiner>()
            .single()
            .mDeadSequence
        assertEquals(0, deadKeys.length)
        assertEquals(0, deadKeys.capacity())
        assertEquals("", chain.composingWordWithCombiningFeedback.toString())
    }
}
