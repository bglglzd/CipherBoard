// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.content.Intent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ContactDetailsExportTest {
    @Test
    fun fingerprintExportContainsOnlyPublicFingerprint() {
        val fingerprint = "01234567 89ABCDEF"

        val intent = ContactDetailsActivity.createFingerprintExportIntent(fingerprint)

        assertEquals(Intent.ACTION_SEND, intent.action)
        assertEquals("text/plain", intent.type)
        assertEquals(fingerprint, intent.getStringExtra(Intent.EXTRA_TEXT))
        assertEquals(setOf(Intent.EXTRA_TEXT), intent.extras?.keySet())
        assertNull(intent.data)
        assertNull(intent.clipData)
        assertNull(intent.component)
        assertNull(intent.`package`)
    }
}
