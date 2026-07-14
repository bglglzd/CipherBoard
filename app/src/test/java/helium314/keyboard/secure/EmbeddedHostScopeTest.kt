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
    fun `same metadata with another host connection is rejected`() {
        val originalToken = mock(IBinder::class.java)
        val otherToken = mock(IBinder::class.java)
        val originalConnection = Any()
        val otherConnection = Any()
        val editor = editorInfo()
        val scope = EmbeddedHostScope.from(editor, HOST_UID, originalToken, originalConnection)

        assertNotNull(scope)
        assertTrue(requireNotNull(scope).matches(editor, HOST_UID, originalToken, originalConnection))
        assertTrue(scope.matches(editorInfo(), HOST_UID, null, originalConnection))
        assertFalse(scope.matches(editorInfo(), HOST_UID, originalToken, otherConnection))
        assertFalse(scope.matches(editorInfo(), HOST_UID, otherToken, otherConnection))
        assertFalse(scope.matches(editorInfo(), HOST_UID, null, otherConnection))
        assertFalse(scope.matches(editorInfo(), HOST_UID, null, null))
    }

    @Test
    fun `unlock rebind replaces token only when metadata still matches`() {
        val originalToken = mock(IBinder::class.java)
        val rejectedToken = mock(IBinder::class.java)
        val unlockToken = mock(IBinder::class.java)
        val originalConnection = Any()
        val rejectedConnection = Any()
        val unlockConnection = Any()
        val editor = editorInfo()
        val scope = requireNotNull(
            EmbeddedHostScope.from(editor, HOST_UID, originalToken, originalConnection),
        )

        assertFalse(scope.rebindAfterUnlock(editor, HOST_UID, unlockToken, unlockConnection))
        scope.armUnlockRebind()
        assertFalse(
            scope.rebindAfterUnlock(
                editorInfo(fieldName = "another-field"),
                HOST_UID,
                rejectedToken,
                rejectedConnection,
            ),
        )
        assertTrue(scope.matches(editor, HOST_UID, originalToken, originalConnection))
        assertFalse(scope.matches(editor, HOST_UID, rejectedToken, rejectedConnection))

        assertTrue(scope.rebindAfterUnlock(editorInfo(), HOST_UID, unlockToken, unlockConnection))
        assertFalse(scope.matches(editor, HOST_UID, originalToken, originalConnection))
        assertTrue(scope.matches(editorInfo(), HOST_UID, unlockToken, unlockConnection))
        assertFalse(scope.rebindAfterUnlock(editorInfo(), HOST_UID, rejectedToken, rejectedConnection))
        assertTrue(scope.matches(editor, HOST_UID, unlockToken, unlockConnection))
    }

    @Test
    fun `scope creation requires valid editor identity and live connection`() {
        val token = mock(IBinder::class.java)
        val connection = Any()

        assertNull(EmbeddedHostScope.from(null, HOST_UID, token, connection))
        assertNull(EmbeddedHostScope.from(editorInfo(packageName = ""), HOST_UID, token, connection))
        assertNull(EmbeddedHostScope.from(editorInfo(), -1, token, connection))
        assertNull(EmbeddedHostScope.from(editorInfo(), HOST_UID, token, null))
        assertNotNull(EmbeddedHostScope.from(editorInfo(), HOST_UID, null, connection))
    }

    @Test
    fun `live connection without framework token accepts ordinary null-type editor`() {
        val connection = Any()
        val editor = editorInfo(inputType = InputType.TYPE_NULL)
        val scope = requireNotNull(EmbeddedHostScope.from(editor, HOST_UID, null, connection))

        assertTrue(scope.matches(editorInfo(inputType = InputType.TYPE_NULL), HOST_UID, null, connection))
        assertFalse(scope.matches(editorInfo(inputType = InputType.TYPE_NULL), HOST_UID, null, Any()))
    }

    private fun editorInfo(
        packageName: String = HOST_PACKAGE,
        fieldName: String = HOST_FIELD_NAME,
        inputType: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE,
    ) = EditorInfo().apply {
        this.packageName = packageName
        fieldId = View.NO_ID
        this.fieldName = fieldName
        this.inputType = inputType
        imeOptions = EditorInfo.IME_ACTION_NONE
    }

    private companion object {
        const val HOST_PACKAGE = "example.host"
        const val HOST_FIELD_NAME = "message"
        const val HOST_UID = 12345
    }
}
