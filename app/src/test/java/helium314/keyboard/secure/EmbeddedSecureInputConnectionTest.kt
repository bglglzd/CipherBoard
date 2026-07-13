// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.Context
import android.text.Editable
import android.text.SpannableStringBuilder
import android.view.View
import androidx.test.core.app.ApplicationProvider
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EmbeddedSecureInputConnectionTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun `editing stays in the local bounded buffer and batches callbacks`() {
        var changeCount = 0
        val connection = connection { changeCount++ }

        assertTrue(connection.beginBatchEdit())
        assertTrue(connection.commitText("alpha", 1))
        assertTrue(connection.setSelection(1, 4))
        assertTrue(connection.commitText("X", 1))
        assertEquals(0, changeCount)
        assertTrue(connection.endBatchEdit())

        assertEquals("aXa", connection.editable.toString())
        assertEquals(2, connection.selectionStart())
        assertEquals(2, connection.selectionEnd())
        assertEquals(1, connection.revision)
        assertEquals(1, changeCount)
        assertContentEquals("aXa".toByteArray(StandardCharsets.UTF_8), connection.copyUtf8())
    }

    @Test
    fun `composition updates replace the active composing span`() {
        val connection = connection()

        assertTrue(connection.setComposingText("priv", 1))
        assertTrue(connection.setComposingText("private", 1))
        assertTrue(connection.finishComposingText())
        assertTrue(connection.commitText(" mode", 1))

        assertEquals("private mode", connection.editable.toString())
        assertEquals(12, connection.selectionStart())
    }

    @Test
    fun `code point deletion never splits a supplementary character`() {
        val connection = connection()

        assertTrue(connection.commitText("A\uD83D\uDE00\u0411", 1))
        assertEquals(3, connection.codePointCount())
        assertTrue(connection.deleteSurroundingTextInCodePoints(2, 0))

        assertEquals("A", connection.editable.toString())
        assertEquals(1, connection.codePointCount())
        assertTrue(connection.deleteSurroundingText(1, 0))
        assertTrue(connection.isEmpty())
    }

    @Test
    fun `strict UTF-8 accounting detects malformed surrogate sequences`() {
        val valid = "A\u00E9\u20AC\uD83D\uDE00"
        val connection = connection()

        assertEquals(10, EmbeddedSecureInputConnection.strictUtf8Length(valid))
        assertTrue(connection.commitText(valid, 1))
        assertEquals(10, connection.utf8Length())
        assertContentEquals(valid.toByteArray(StandardCharsets.UTF_8), connection.copyUtf8())

        assertNull(EmbeddedSecureInputConnection.strictUtf8Length("\uD83D"))
        assertNull(EmbeddedSecureInputConnection.strictUtf8Length("\uDE00"))
        assertNull(EmbeddedSecureInputConnection.strictUtf8Length("\uD83DA"))

        val malformed = connection()
        assertTrue(malformed.commitText("\uD83D", 1))
        assertNull(malformed.utf8Length())
        assertFailsWith<IllegalArgumentException> { malformed.copyUtf8() }
    }

    @Test
    fun `draft accepts the exact UTF-16 limit and rejects growth beyond it`() {
        var changeCount = 0
        val connection = connection { changeCount++ }
        val atLimit = "x".repeat(EmbeddedSecureInputConnection.MAX_DRAFT_UTF16_CHARS)

        assertTrue(connection.commitText(atLimit, 1))
        val revisionAtLimit = connection.revision
        assertEquals(EmbeddedSecureInputConnection.MAX_DRAFT_UTF16_CHARS, connection.editable.length)
        assertFalse(connection.commitText("y", 1))

        assertEquals(EmbeddedSecureInputConnection.MAX_DRAFT_UTF16_CHARS, connection.editable.length)
        assertEquals(revisionAtLimit, connection.revision)
        assertEquals(1, changeCount)
    }

    @Test
    fun `wipe clears held editable state and resets selection`() {
        var acceptsInput = true
        var changeCount = 0
        val connection = EmbeddedSecureInputConnection(
            View(context),
            { acceptsInput },
            { changeCount++ },
        )
        val heldEditable: Editable = connection.editable
        assertTrue(connection.commitText("transient-test-draft", 1))
        val revisionBeforeWipe = connection.revision

        connection.wipe()

        assertTrue(connection.isEmpty())
        assertTrue(heldEditable.isEmpty())
        assertEquals(0, connection.selectionStart())
        assertEquals(0, connection.selectionEnd())
        assertEquals(revisionBeforeWipe + 1, connection.revision)
        assertEquals(2, changeCount)

        acceptsInput = false
        assertFalse(connection.commitText("blocked", 1))
        assertTrue(connection.isEmpty())
        assertEquals(2, changeCount)
    }

    @Test
    fun `display copy replaces only the changed range`() {
        val connection = connection()
        val display = SpannableStringBuilder("prefix OLD suffix")

        assertTrue(connection.commitText("prefix NEW suffix", 1))
        connection.copyInto(display)

        assertEquals("prefix NEW suffix", display.toString())
    }

    @Test
    fun `maximum embedded draft can be wiped in one operation`() {
        val connection = connection()
        val content = "z".repeat(EmbeddedSecureInputConnection.MAX_DRAFT_UTF16_CHARS)

        assertTrue(connection.commitText(content, 1))
        connection.wipe()

        assertTrue(connection.isEmpty())
        assertEquals(0, connection.selectionStart())
    }

    private fun connection(
        onChanged: (EmbeddedSecureInputConnection) -> Unit = {},
    ): EmbeddedSecureInputConnection = EmbeddedSecureInputConnection(
        View(context),
        { true },
        onChanged,
    )
}
