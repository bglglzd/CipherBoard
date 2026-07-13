// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PersonalizationStoragePolicyTest {
    @Test
    fun `only an explicit global preference disables and clears personalization`() {
        assertFalse(LatinIME.shouldClearPersonalizationStorage(true, false))
        assertFalse(LatinIME.shouldClearPersonalizationStorage(true, true))
        assertTrue(LatinIME.shouldClearPersonalizationStorage(false, false))
    }

    @Test
    fun `a secure editor never deletes normal keyboard history`() {
        assertFalse(LatinIME.shouldClearPersonalizationStorage(false, true))
    }
}
