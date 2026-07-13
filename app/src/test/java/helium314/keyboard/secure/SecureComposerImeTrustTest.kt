// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.view.ViewStructure
import android.view.KeyEvent
import android.view.inputmethod.EditorInfo
import androidx.test.core.app.ApplicationProvider
import androidx.core.view.inputmethod.EditorInfoCompat
import helium314.keyboard.latin.InputAttributes
import helium314.keyboard.latin.LatinIME
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Answers
import org.mockito.Mockito.mock
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SecureComposerImeTrustTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        Settings.Secure.putString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD, null)
    }

    @Test
    fun `trusts only the installed CipherBoard input method component`() {
        assertFalse(SecureComposerImeTrust.isCipherBoardSelected(context))

        Settings.Secure.putString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
            ComponentName("example.foreign", "example.foreign.Keyboard").flattenToString(),
        )
        assertFalse(SecureComposerImeTrust.isCipherBoardSelected(context))

        Settings.Secure.putString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
            ComponentName(context, LatinIME::class.java).flattenToString(),
        )
        assertTrue(SecureComposerImeTrust.isCipherBoardSelected(context))
    }

    @Test
    fun `malformed selected IME setting is rejected`() {
        Settings.Secure.putString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
            "not-a-component",
        )
        assertFalse(SecureComposerImeTrust.isCipherBoardSelected(context))
    }

    @Test
    fun `plaintext editor refuses a connection after default IME changes`() {
        Settings.Secure.putString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
            ComponentName(context, LatinIME::class.java).flattenToString(),
        )
        val editor = SecurePlaintextEditText(context)
        editor.setText("sensitive-test-value")
        val trustedInfo = EditorInfo()
        assertTrue(editor.onCreateInputConnection(trustedInfo) != null)
        assertTrue(trustedInfo.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
        assertTrue(trustedInfo.imeOptions and EditorInfo.IME_FLAG_NO_EXTRACT_UI != 0)
        assertTrue(trustedInfo.imeOptions and EditorInfo.IME_FLAG_NO_FULLSCREEN != 0)
        assertTrue(trustedInfo.privateImeOptions == InputAttributes.CIPHERBOARD_SECURE_EDITOR_OPTION)
        assertTrue(
            EditorInfoCompat.getInitialTextBeforeCursor(trustedInfo, 1024, 0).isNullOrEmpty(),
        )
        assertTrue(
            EditorInfoCompat.getInitialTextAfterCursor(trustedInfo, 1024, 0).isNullOrEmpty(),
        )

        Settings.Secure.putString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
            ComponentName("example.foreign", "example.foreign.Keyboard").flattenToString(),
        )

        assertNull(editor.onCreateInputConnection(EditorInfo()))
        assertTrue(editor.text.isEmpty())
    }

    @Test
    fun `assist autofill and content capture structures never receive plaintext`() {
        val secret = "sensitive-assist-test-value"
        val editor = SecurePlaintextEditText(context).apply { setText(secret) }
        val observedArguments = mutableListOf<Any?>()
        val structure = mock(ViewStructure::class.java) { invocation ->
            observedArguments.addAll(invocation.arguments)
            Answers.RETURNS_DEFAULTS.answer(invocation)
        }

        editor.onProvideStructure(structure)
        editor.onProvideAutofillStructure(structure, 0)
        editor.onProvideContentCaptureStructure(structure, 0)

        verify(structure, times(3)).setDataIsSensitive(true)
        assertFalse(observedArguments.any { it?.toString()?.contains(secret) == true })
    }

    @Test
    fun `clearing plaintext forgets undo history and blocks undo shortcuts`() {
        val editor = SecurePlaintextEditText(context)
        editor.setText("sensitive-undo-test-value")
        editor.append("-changed")

        editor.clearAndForgetHistory()

        assertTrue(editor.text.isEmpty())
        assertFalse(editor.onTextContextMenuItem(android.R.id.undo))
        assertFalse(editor.onTextContextMenuItem(android.R.id.redo))
        assertTrue(
            editor.onKeyShortcut(
                KeyEvent.KEYCODE_Z,
                KeyEvent(0, 0, KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_Z, 0, KeyEvent.META_CTRL_ON),
            ),
        )
        assertTrue(editor.text.isEmpty())
    }

    @Test
    fun `handoff requires every security gate`() {
        assertTrue(secureHandoffAllowed(true, true, true, true, true))
        val denied = listOf(
            secureHandoffAllowed(false, true, true, true, true),
            secureHandoffAllowed(true, false, true, true, true),
            secureHandoffAllowed(true, true, false, true, true),
            secureHandoffAllowed(true, true, true, false, true),
            secureHandoffAllowed(true, true, true, true, false),
        )
        assertTrue(denied.none { it })
    }
}
