// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin.inputlogic

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InputLogicSecurityPolicyTest {
    @Test
    fun `private editor never emits detailed input debug payloads`() {
        assertFalse(InputLogic.shouldEmitDetailedInputDebug(true, true))
        assertFalse(InputLogic.shouldEmitDetailedInputDebug(false, true))
    }

    @Test
    fun `normal editor preserves explicitly enabled upstream diagnostics`() {
        assertTrue(InputLogic.shouldEmitDetailedInputDebug(true, false))
        assertFalse(InputLogic.shouldEmitDetailedInputDebug(false, false))
    }
}
