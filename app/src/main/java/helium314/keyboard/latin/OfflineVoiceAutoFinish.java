// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin;

import android.os.Handler;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/** Schedules the short continuation window after Vosk detects an utterance endpoint. */
final class OfflineVoiceAutoFinish {
    static final long GRACE_MILLIS = 700L;

    private final Handler handler;
    @Nullable private Runnable pending;

    OfflineVoiceAutoFinish(@NonNull final Handler handler) {
        this.handler = handler;
    }

    void schedule(@NonNull final Runnable action) {
        cancel();
        pending = () -> {
            pending = null;
            action.run();
        };
        handler.postDelayed(pending, GRACE_MILLIS);
    }

    void cancel() {
        if (pending == null) return;
        handler.removeCallbacks(pending);
        pending = null;
    }
}
