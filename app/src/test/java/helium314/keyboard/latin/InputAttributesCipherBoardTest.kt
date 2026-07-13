// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import android.text.InputType
import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertTrue
import org.junit.Test

class InputAttributesCipherBoardTest {
    @Test
    fun cipherBoardEditorsAlwaysDisableLearning() {
        val editorInfo = EditorInfo().apply {
            packageName = BuildConfig.APPLICATION_ID
            inputType = InputType.TYPE_CLASS_TEXT
            imeOptions = 0
            privateImeOptions = InputAttributes.CIPHERBOARD_SECURE_EDITOR_OPTION
        }

        val attributes = InputAttributes(editorInfo, false, BuildConfig.APPLICATION_ID)

        assertTrue(attributes.mNoLearning)
        assertTrue(attributes.mIsCipherBoardEditor)
        assertTrue(attributes.mIsCipherBoardSecureEditor)
        assertTrue(!attributes.mShouldShowVoiceInputKey)
    }

    @Test
    fun unmarkedCipherBoardEditorIsNotTreatedAsSecureComposer() {
        val editorInfo = EditorInfo().apply {
            packageName = BuildConfig.APPLICATION_ID
            inputType = InputType.TYPE_CLASS_TEXT
        }

        val attributes = InputAttributes(editorInfo, false, BuildConfig.APPLICATION_ID)

        assertTrue(attributes.mIsCipherBoardEditor)
        assertTrue(!attributes.mIsCipherBoardSecureEditor)
        assertTrue(attributes.mNoLearning)
    }
}
