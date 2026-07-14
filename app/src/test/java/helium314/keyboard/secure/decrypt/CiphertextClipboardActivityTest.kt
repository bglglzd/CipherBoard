// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import helium314.keyboard.latin.R
import java.util.ArrayDeque
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class CiphertextClipboardActivityTest {
    @Test
    fun `fallback reads ciphertext only after explicit confirmation and leaves clipboard unchanged`() {
        val controller = Robolectric.buildActivity(CiphertextClipboardActivity::class.java)
            .create()
            .start()
            .resume()
            .visible()
        val activity = controller.get()
        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val ciphertext = "CB1:ClipboardCiphertext_123"
        clipboard.setPrimaryClip(ClipData("", arrayOf("text/plain"), ClipData.Item(ciphertext)))

        assertTrue(
            activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
        )
        assertNull(shadowOf(activity).nextStartedActivity)

        val action = descendants<Button>(activity.findViewById(android.R.id.content)).single {
            it.text.toString() == activity.getString(R.string.secure_clipboard_decrypt_action)
        }
        action.performClick()

        val viewerIntent = assertNotNull(shadowOf(activity).nextStartedActivity)
        assertEquals(SecureMessageViewerActivity::class.java.name, viewerIntent.component?.className)
        val transportedStrings = viewerIntent.extras?.keySet().orEmpty().mapNotNull { key ->
            @Suppress("DEPRECATION")
            viewerIntent.extras?.get(key) as? String
        }
        assertEquals(listOf(ciphertext), transportedStrings)
        assertEquals(ciphertext, clipboard.primaryClip?.getItemAt(0)?.text?.toString())
        assertFalse(clipboard.primaryClip?.getItemAt(0)?.text?.toString().orEmpty().contains("plaintext"))
        assertTrue(activity.isFinishing)

        controller.pause().stop().destroy()
    }

    private inline fun <reified T : View> descendants(root: View): List<T> {
        val matches = mutableListOf<T>()
        val pending = ArrayDeque<View>()
        pending.add(root)
        while (pending.isNotEmpty()) {
            val view = pending.removeFirst()
            if (view is T) matches += view
            if (view is ViewGroup) {
                for (index in 0 until view.childCount) pending.add(view.getChildAt(index))
            }
        }
        return matches
    }
}
