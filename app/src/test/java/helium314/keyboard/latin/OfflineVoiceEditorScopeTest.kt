// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import android.text.InputType
import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineVoiceEditorScopeTest {
    @Test
    fun `same editor metadata is accepted after permission activity rebind`() {
        val scope = OfflineVoiceEditorScope.from(editorInfo(), HOST_UID)

        assertNotNull(scope)
        assertTrue(requireNotNull(scope).matches(editorInfo(), HOST_UID))
    }

    @Test
    fun `different host or editor is rejected`() {
        val scope = requireNotNull(OfflineVoiceEditorScope.from(editorInfo(), HOST_UID))

        assertFalse(scope.matches(editorInfo(packageName = "another.app"), HOST_UID))
        assertFalse(scope.matches(editorInfo(fieldId = 8), HOST_UID))
        assertFalse(scope.matches(editorInfo(fieldName = "another"), HOST_UID))
        assertFalse(scope.matches(editorInfo(inputType = InputType.TYPE_CLASS_NUMBER), HOST_UID))
        assertFalse(scope.matches(editorInfo(imeOptions = EditorInfo.IME_ACTION_SEND), HOST_UID))
        assertFalse(scope.matches(editorInfo(privateImeOptions = "another"), HOST_UID))
        assertFalse(scope.matches(editorInfo(), HOST_UID + 1))
        assertFalse(scope.matches(null, HOST_UID))
    }

    @Test
    fun `invalid pending editor identity is rejected`() {
        assertNull(OfflineVoiceEditorScope.from(null, HOST_UID))
        assertNull(OfflineVoiceEditorScope.from(editorInfo(packageName = ""), HOST_UID))
        assertNull(OfflineVoiceEditorScope.from(editorInfo(), -1))
    }

    private fun editorInfo(
        packageName: String = "example.host",
        fieldId: Int = 7,
        fieldName: String = "message",
        inputType: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE,
        imeOptions: Int = EditorInfo.IME_ACTION_NONE,
        privateImeOptions: String = "example.private",
    ) = EditorInfo().apply {
        this.packageName = packageName
        this.fieldId = fieldId
        this.fieldName = fieldName
        this.inputType = inputType
        this.imeOptions = imeOptions
        this.privateImeOptions = privateImeOptions
    }

    private companion object {
        const val HOST_UID = 12345
    }
}
