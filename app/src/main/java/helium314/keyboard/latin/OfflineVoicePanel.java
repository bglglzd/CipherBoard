// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin;

import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.graphics.Color;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;

import helium314.keyboard.latin.common.ColorType;
import helium314.keyboard.latin.common.Colors;
import helium314.keyboard.latin.settings.Settings;

/** Visual feedback for the local voice session, rendered entirely inside the IME window. */
final class OfflineVoicePanel {
    private static final long PULSE_DURATION_MILLIS = 850L;

    private final Runnable finishAction;
    @Nullable private View panel;
    @Nullable private View keyboardFrame;
    @Nullable private View pulse;
    @Nullable private ImageButton microphone;
    @Nullable private TextView status;
    @Nullable private TextView transcript;
    @Nullable private TextView hint;
    @Nullable private TextView privacy;
    @Nullable private ObjectAnimator pulseAnimator;

    OfflineVoicePanel(@NonNull final Runnable finishAction) {
        this.finishAction = finishAction;
    }

    void attach(@NonNull final View inputView) {
        stopPulse();
        panel = inputView.findViewById(R.id.offline_voice_panel);
        keyboardFrame = inputView.findViewById(R.id.main_keyboard_frame);
        pulse = inputView.findViewById(R.id.offline_voice_pulse);
        microphone = inputView.findViewById(R.id.offline_voice_microphone);
        status = inputView.findViewById(R.id.offline_voice_status);
        transcript = inputView.findViewById(R.id.offline_voice_transcript);
        hint = inputView.findViewById(R.id.offline_voice_hint);
        privacy = inputView.findViewById(R.id.offline_voice_privacy);

        if (panel == null || keyboardFrame == null || pulse == null || microphone == null || status == null
                || transcript == null || hint == null || privacy == null) {
            detach();
            return;
        }
        microphone.setOnClickListener(ignored -> finishAction.run());
        applyKeyboardColors();
        panel.setVisibility(View.GONE);
    }

    void show(
            @StringRes final int statusMessage,
            @NonNull final String recognizedText,
            final boolean listening) {
        if (panel == null || keyboardFrame == null || pulse == null || microphone == null || status == null
                || transcript == null || hint == null) {
            return;
        }
        matchKeyboardHeight();
        panel.setVisibility(View.VISIBLE);
        status.setText(statusMessage);
        final boolean showTranscript = listening || !recognizedText.isEmpty();
        transcript.setVisibility(showTranscript ? View.VISIBLE : View.INVISIBLE);
        transcript.setText(recognizedText.isEmpty() && listening
                ? panel.getContext().getString(R.string.offline_voice_speak_now) : recognizedText);
        hint.setVisibility(listening ? View.VISIBLE : View.INVISIBLE);
        final boolean canStop = statusMessage != R.string.offline_voice_processing;
        microphone.setEnabled(canStop);
        microphone.setAlpha(canStop ? 1.0f : 0.72f);
        if (listening) {
            startPulse();
        } else {
            stopPulse();
        }
    }

    void hide() {
        stopPulse();
        if (panel != null) panel.setVisibility(View.GONE);
    }

    void detach() {
        hide();
        if (microphone != null) microphone.setOnClickListener(null);
        panel = null;
        keyboardFrame = null;
        pulse = null;
        microphone = null;
        status = null;
        transcript = null;
        hint = null;
        privacy = null;
    }

    private void applyKeyboardColors() {
        if (panel == null || pulse == null || microphone == null || status == null
                || transcript == null || hint == null || privacy == null) {
            return;
        }
        final Colors colors = Settings.getValues().mColors;
        panel.setBackgroundColor(colors.get(ColorType.MAIN_BACKGROUND));
        colors.setColor(pulse.getBackground(), ColorType.ACTION_KEY_BACKGROUND);
        colors.setColor(microphone.getBackground(), ColorType.ACTION_KEY_BACKGROUND);
        colors.setColor(microphone, ColorType.ACTION_KEY_ICON);
        final int primaryText = colors.get(ColorType.KEY_TEXT);
        final int secondaryText = Color.argb(
                166, Color.red(primaryText), Color.green(primaryText), Color.blue(primaryText));
        status.setTextColor(primaryText);
        transcript.setTextColor(primaryText);
        hint.setTextColor(secondaryText);
        privacy.setTextColor(secondaryText);
    }

    private void matchKeyboardHeight() {
        if (panel == null || keyboardFrame == null || keyboardFrame.getHeight() <= 0) return;
        final FrameLayout.LayoutParams parameters =
                (FrameLayout.LayoutParams) panel.getLayoutParams();
        if (parameters.height == keyboardFrame.getHeight() && parameters.gravity == Gravity.BOTTOM) {
            return;
        }
        parameters.height = keyboardFrame.getHeight();
        parameters.gravity = Gravity.BOTTOM;
        panel.setLayoutParams(parameters);
    }

    private void startPulse() {
        if (pulse == null || pulseAnimator != null) return;
        pulse.setAlpha(0.35f);
        pulseAnimator = ObjectAnimator.ofPropertyValuesHolder(
                pulse,
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.82f, 1.13f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.82f, 1.13f),
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.38f, 0.08f));
        pulseAnimator.setDuration(PULSE_DURATION_MILLIS);
        pulseAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        pulseAnimator.setRepeatCount(ObjectAnimator.INFINITE);
        pulseAnimator.setRepeatMode(ObjectAnimator.REVERSE);
        pulseAnimator.start();
    }

    private void stopPulse() {
        if (pulseAnimator != null) {
            pulseAnimator.cancel();
            pulseAnimator = null;
        }
        if (pulse != null) {
            pulse.setScaleX(1.0f);
            pulse.setScaleY(1.0f);
            pulse.setAlpha(0.18f);
        }
    }
}
