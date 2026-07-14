// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class EmbeddedDecryptSurfaceTest {
    private val context = ApplicationProvider.getApplicationContext<Application>()
    private val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    @Test
    fun `ciphertext clipboard reader requires one bounded explicit text item`() {
        val ciphertext = "CB1:BoundedCiphertext_123"
        clipboard.setPrimaryClip(ClipData("", arrayOf("text/plain"), ClipData.Item(ciphertext)))

        assertEquals(ciphertext, CiphertextClipboardReader.read(context))
        assertEquals(ciphertext, clipboard.primaryClip?.getItemAt(0)?.text?.toString())

        val multiple = ClipData("", arrayOf("text/plain"), ClipData.Item(ciphertext)).apply {
            addItem(ClipData.Item("CB1:AnotherPart"))
        }
        clipboard.setPrimaryClip(multiple)
        assertNull(CiphertextClipboardReader.read(context))

        val oversized = "C".repeat(CiphertextSelection.MAX_SELECTION_CHARS + 1)
        clipboard.setPrimaryClip(ClipData("", arrayOf("text/plain"), ClipData.Item(oversized)))
        assertNull(CiphertextClipboardReader.read(context))
    }

    @Test
    fun `embedded plaintext surface is drawing only and wipes its owned text`() {
        val ownedBytes = WipeablePlaintext.takeOwnership("surface-only plaintext".encodeToByteArray())
        val text = requireNotNull(WipeableText.decodeUtf8(ownedBytes))
        ownedBytes.close()
        val view = SecurePlaintextView(context)

        view.setSecureText(text)

        assertFalse(view.isFocusable)
        assertFalse(view.isFocusableInTouchMode)
        assertFalse(view.isLongClickable)
        assertFalse(view.isSaveEnabled)
        assertNull(view.contentDescription)
        assertEquals(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS, view.importantForAccessibility)
        assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, view.importantForAutofill)
        assertEquals(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS, view.importantForContentCapture)
        assertTrue(text.isNotEmpty())

        view.clearSecureText()

        assertEquals(0, text.length)
    }

    @Test
    fun `pending display is acknowledged only after an allowed draw`() {
        val ownedBytes = WipeablePlaintext.takeOwnership("render acknowledgement".encodeToByteArray())
        val text = requireNotNull(WipeableText.decodeUtf8(ownedBytes))
        ownedBytes.close()
        val view = SecurePlaintextView(context)
        var allowDraw = false
        var beforeDrawCount = 0
        var drawnCount = 0
        view.beforeSecureTextDraw = {
            beforeDrawCount++
            allowDraw
        }
        view.onSecureTextDrawn = { drawnCount++ }
        view.setSecureText(text)
        val width = 480
        val height = 240
        view.measure(
            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY),
        )
        view.layout(0, 0, width, height)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)

        view.draw(canvas)

        assertEquals(1, beforeDrawCount)
        assertEquals(0, drawnCount)
        assertTrue(text.isNotEmpty())

        allowDraw = true
        view.draw(canvas)
        view.draw(canvas)

        assertEquals(2, beforeDrawCount)
        assertEquals(1, drawnCount)
        view.clearSecureText()
        assertEquals(0, text.length)
        bitmap.recycle()
    }
}
