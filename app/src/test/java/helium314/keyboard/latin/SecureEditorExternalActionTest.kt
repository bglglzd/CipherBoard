// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import helium314.keyboard.keyboard.internal.keyboard_parser.floris.KeyCode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureEditorExternalActionTest {
    @Test
    fun secureEditorBlocksExternalAndClipboardActions() {
        val blocked = intArrayOf(
            KeyCode.VOICE_INPUT,
            KeyCode.SYSTEM_INPUT_METHOD_PICKER,
            KeyCode.CLIPBOARD,
            KeyCode.CLIPBOARD_PASTE,
            KeyCode.CLIPBOARD_SELECT_ALL,
            KeyCode.CLIPBOARD_SELECT_WORD,
            KeyCode.CLIPBOARD_COPY,
            KeyCode.CLIPBOARD_COPY_ALL,
            KeyCode.CLIPBOARD_CUT,
            KeyCode.CLIPBOARD_CLEAR_HISTORY,
            KeyCode.UNDO,
            KeyCode.REDO,
        )
        blocked.forEach { keyCode ->
            assertTrue("expected secure block for $keyCode", LatinIME.blocksExternalInputAction(true, keyCode))
            assertFalse(LatinIME.blocksExternalInputAction(false, keyCode))
        }
        assertFalse(LatinIME.blocksExternalInputAction(true, KeyCode.LANGUAGE_SWITCH))
    }
}
