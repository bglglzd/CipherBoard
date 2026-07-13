// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.os.IBinder
import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.mock

class EmbeddedHostScopeTest {
    @Test
    fun `same metadata with another connection token is rejected`() {
        val originalToken = mock(IBinder::class.java)
        val otherToken = mock(IBinder::class.java)
        val editor = editorInfo()
        val scope = EmbeddedHostScope.from(editor, HOST_UID, originalToken)

        assertNotNull(scope)
        assertTrue(requireNotNull(scope).matches(editor, HOST_UID, originalToken))
        assertFalse(scope.matches(editorInfo(), HOST_UID, otherToken))
        assertFalse(scope.matches(editorInfo(), HOST_UID, null))
    }

    @Test
    fun `unlock rebind replaces token only when metadata still matches`() {
        val originalToken = mock(IBinder::class.java)
        val rejectedToken = mock(IBinder::class.java)
        val unlockToken = mock(IBinder::class.java)
        val editor = editorInfo()
        val scope = requireNotNull(EmbeddedHostScope.from(editor, HOST_UID, originalToken))

        assertFalse(scope.rebindAfterUnlock(editor, HOST_UID, unlockToken))
        scope.armUnlockRebind()
        assertFalse(scope.rebindAfterUnlock(editorInfo(fieldName = "another-field"), HOST_UID, rejectedToken))
        assertTrue(scope.matches(editor, HOST_UID, originalToken))
        assertFalse(scope.matches(editor, HOST_UID, rejectedToken))

        assertTrue(scope.rebindAfterUnlock(editorInfo(), HOST_UID, unlockToken))
        assertFalse(scope.matches(editor, HOST_UID, originalToken))
        assertTrue(scope.matches(editorInfo(), HOST_UID, unlockToken))
        assertFalse(scope.rebindAfterUnlock(editorInfo(), HOST_UID, rejectedToken))
        assertTrue(scope.matches(editor, HOST_UID, unlockToken))
    }

    @Test
    fun `scope creation requires valid identity and non-null token`() {
        val token = mock(IBinder::class.java)

        assertNull(EmbeddedHostScope.from(null, HOST_UID, token))
        assertNull(EmbeddedHostScope.from(editorInfo(packageName = ""), HOST_UID, token))
        assertNull(EmbeddedHostScope.from(editorInfo(), -1, token))
        assertNull(EmbeddedHostScope.from(editorInfo(), HOST_UID, null))
    }

    private fun editorInfo(
        packageName: String = HOST_PACKAGE,
        fieldName: String = HOST_FIELD_NAME,
    ) = EditorInfo().apply {
        this.packageName = packageName
        fieldId = View.NO_ID
        this.fieldName = fieldName
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        imeOptions = EditorInfo.IME_ACTION_NONE
    }

    private companion object {
        const val HOST_PACKAGE = "example.host"
        const val HOST_FIELD_NAME = "message"
        const val HOST_UID = 12345
    }
}
