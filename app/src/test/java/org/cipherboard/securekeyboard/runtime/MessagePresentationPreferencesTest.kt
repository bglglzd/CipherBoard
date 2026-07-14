// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.cipherboard.cryptocore.TransportPresentation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MessagePresentationPreferencesTest {
    private val context get() = ApplicationProvider.getApplicationContext<Context>()

    @Before
    fun clearPreferences() {
        context.getSharedPreferences("cipherboard_public_settings", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun defaultsToCompactForBackwardCompatibility() {
        assertEquals(TransportPresentation.COMPACT, MessagePresentationPreferences.read(context))
    }

    @Test
    fun persistsEverySupportedPresentation() {
        TransportPresentation.entries.forEach { presentation ->
            assertTrue(MessagePresentationPreferences.write(context, presentation))
            assertEquals(presentation, MessagePresentationPreferences.read(context))
        }
    }

    @Test
    fun unknownStoredValueFallsBackToCompact() {
        context.getSharedPreferences("cipherboard_public_settings", Context.MODE_PRIVATE)
            .edit()
            .putString("message_transport_presentation", "FUTURE_UNKNOWN_VALUE")
            .commit()

        assertEquals(TransportPresentation.COMPACT, MessagePresentationPreferences.read(context))
    }
}
