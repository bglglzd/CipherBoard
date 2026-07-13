// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.Context
import android.view.inputmethod.EditorInfo
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SecureDraftViewTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun `display owns one non-editor buffer without a system input connection`() {
        val view = SecureDraftView(context)

        assertSame(view.displayBuffer, view.text)
        assertFalse(view.onCheckIsTextEditor())
        assertNull(view.onCreateInputConnection(EditorInfo()))
    }
}
