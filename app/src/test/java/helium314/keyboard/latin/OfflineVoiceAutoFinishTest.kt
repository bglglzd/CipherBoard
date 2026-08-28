// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import android.os.Handler
import android.os.Looper
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.LooperMode

@RunWith(RobolectricTestRunner::class)
@LooperMode(LooperMode.Mode.PAUSED)
class OfflineVoiceAutoFinishTest {
    @Test
    fun finalizedUtteranceFinishesAfterContinuationGrace() {
        val autoFinish = OfflineVoiceAutoFinish(Handler(Looper.getMainLooper()))
        var finishes = 0

        autoFinish.schedule { finishes += 1 }
        shadowOf(Looper.getMainLooper()).idleFor(
            Duration.ofMillis(OfflineVoiceAutoFinish.GRACE_MILLIS - 1),
        )
        assertEquals(0, finishes)

        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(1))
        assertEquals(1, finishes)
    }

    @Test
    fun resumedSpeechCancelsPendingAutomaticFinish() {
        val autoFinish = OfflineVoiceAutoFinish(Handler(Looper.getMainLooper()))
        var finishes = 0

        autoFinish.schedule { finishes += 1 }
        autoFinish.cancel()
        shadowOf(Looper.getMainLooper()).idleFor(
            Duration.ofMillis(OfflineVoiceAutoFinish.GRACE_MILLIS),
        )

        assertEquals(0, finishes)
    }
}
