// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.StringRes;
import androidx.core.content.ContextCompat;

import org.vosk.LibVosk;
import org.vosk.LogLevel;
import org.vosk.Model;
import org.vosk.Recognizer;
import org.vosk.android.RecognitionListener;
import org.vosk.android.SpeechService;

import java.io.File;
import java.util.ArrayList;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Owns one explicit, in-memory, fully offline voice-dictation session. */
final class OfflineVoiceInputController {
    interface Callback {
        void showStatus(@StringRes int message);
        void commitRecognizedText(@NonNull String text);
        void onSessionClosed();
    }

    private enum State { IDLE, LOADING, LISTENING, STOPPING }

    private static final float SAMPLE_RATE = 16_000.0f;
    private static final long MAX_LISTENING_MILLIS = 60_000L;
    private static final int MAX_TRANSCRIPT_CHARS = 20_000;
    private static final int MAX_SEGMENTS = 256;

    private final LatinIME service;
    private final Callback callback;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService loader = Executors.newSingleThreadExecutor(runnable -> {
        final Thread thread = new Thread(runnable, "CipherBoardOfflineVoiceModel");
        thread.setDaemon(true);
        return thread;
    });
    private final ArrayList<String> completedSegments = new ArrayList<>();
    private int completedCharacters;

    private State state = State.IDLE;
    private int generation;
    private SpeechService speechService;
    private Recognizer recognizer;
    private Model model;
    private Runnable listeningTimeout;

    OfflineVoiceInputController(
            @NonNull final LatinIME service, @NonNull final Callback callback) {
        this.service = service;
        this.callback = callback;
    }

    void toggle(final Locale locale) {
        if (state != State.IDLE) {
            stopOrCancel();
            return;
        }
        if (!hasMicrophonePermission()) {
            final Intent intent = new Intent(service, OfflineVoicePermissionActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NO_ANIMATION);
            service.startActivity(intent);
            return;
        }
        start(locale);
    }

    boolean hasMicrophonePermission() {
        return ContextCompat.checkSelfPermission(service, Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED;
    }

    boolean isIdle() {
        return state == State.IDLE;
    }

    void startAfterPermission(final Locale locale) {
        if (state != State.IDLE || !hasMicrophonePermission()) {
            return;
        }
        start(locale);
    }

    private void start(final Locale locale) {
        final int session = ++generation;
        final String language = OfflineVoiceTextKt.offlineVoiceModelLanguage(locale);
        state = State.LOADING;
        completedSegments.clear();
        completedCharacters = 0;
        callback.showStatus(R.string.offline_voice_preparing);
        loader.execute(() -> {
            Model loadedModel = null;
            try {
                LibVosk.setLogLevel(LogLevel.WARNINGS);
                final File modelDirectory = OfflineVoiceModelAssets.prepare(service, language);
                loadedModel = new Model(modelDirectory.getAbsolutePath());
                final Model readyModel = loadedModel;
                mainHandler.post(() -> beginListening(session, readyModel));
            } catch (Exception | LinkageError exception) {
                closeModelQuietly(loadedModel);
                mainHandler.post(() -> fail(session, R.string.offline_voice_model_error));
            }
        });
    }

    private void beginListening(final int session, @NonNull final Model readyModel) {
        if (session != generation || state != State.LOADING) {
            closeModelQuietly(readyModel);
            return;
        }
        try {
            model = readyModel;
            recognizer = new Recognizer(model, SAMPLE_RATE);
            speechService = new SpeechService(recognizer, SAMPLE_RATE);
            state = State.LISTENING;
            if (!speechService.startListening(new Listener(session))) {
                fail(session, R.string.offline_voice_microphone_error);
                return;
            }
            callback.showStatus(R.string.offline_voice_listening);
            listeningTimeout = () -> stopForResult(session);
            mainHandler.postDelayed(listeningTimeout, MAX_LISTENING_MILLIS);
        } catch (Exception | LinkageError exception) {
            fail(session, R.string.offline_voice_microphone_error);
        }
    }

    private void stopOrCancel() {
        if (state == State.LOADING) {
            generation += 1;
            state = State.IDLE;
            completedSegments.clear();
            completedCharacters = 0;
            callback.showStatus(R.string.offline_voice_cancelled);
            callback.onSessionClosed();
            return;
        }
        if (state == State.LISTENING) stopForResult(generation);
    }

    private void stopForResult(final int session) {
        if (session != generation || state != State.LISTENING || speechService == null) return;
        state = State.STOPPING;
        callback.showStatus(R.string.offline_voice_processing);
        try {
            speechService.stop();
        } catch (RuntimeException | LinkageError exception) {
            fail(session, R.string.offline_voice_microphone_error);
        }
    }

    void cancel() {
        generation += 1;
        cancelListeningTimeout();
        cancelSpeechQuietly();
        releaseNativeResources();
        completedSegments.clear();
        completedCharacters = 0;
        state = State.IDLE;
    }

    void destroy() {
        cancel();
        loader.shutdownNow();
    }

    private void finish(final int session, final String finalJson) {
        if (session != generation || state == State.IDLE) return;
        addSegment(finalJson);
        final String text = OfflineVoiceTextKt.joinOfflineVoiceSegments(completedSegments);
        cancelListeningTimeout();
        releaseNativeResources();
        completedSegments.clear();
        completedCharacters = 0;
        state = State.IDLE;
        if (text.isEmpty()) {
            callback.showStatus(R.string.offline_voice_no_speech);
        } else {
            callback.commitRecognizedText(text);
            callback.showStatus(R.string.offline_voice_inserted);
        }
        callback.onSessionClosed();
    }

    private void fail(final int session, @StringRes final int message) {
        if (session != generation) return;
        generation += 1;
        cancelListeningTimeout();
        cancelSpeechQuietly();
        releaseNativeResources();
        completedSegments.clear();
        completedCharacters = 0;
        state = State.IDLE;
        callback.showStatus(message);
        callback.onSessionClosed();
    }

    private void addSegment(final String json) {
        final String text = OfflineVoiceTextKt.parseOfflineVoiceResult(json);
        if (text == null || completedSegments.size() >= MAX_SEGMENTS) return;
        final int separator = completedSegments.isEmpty() ? 0 : 1;
        final int remaining = MAX_TRANSCRIPT_CHARS - completedCharacters - separator;
        if (remaining <= 0) return;
        final String bounded = text.length() <= remaining ? text : text.substring(0, remaining);
        if (bounded.isEmpty()) return;
        completedSegments.add(bounded);
        completedCharacters += separator + bounded.length();
    }

    private void releaseNativeResources() {
        if (speechService != null) {
            try {
                speechService.shutdown();
            } catch (RuntimeException | LinkageError ignored) {
                // Best-effort cleanup continues with the recognizer and model.
            }
            speechService = null;
        }
        if (recognizer != null) {
            try {
                recognizer.close();
            } catch (RuntimeException | LinkageError ignored) {
                // Continue releasing the model even if the native wrapper is already invalid.
            }
            recognizer = null;
        }
        if (model != null) {
            closeModelQuietly(model);
            model = null;
        }
    }

    private void cancelSpeechQuietly() {
        if (speechService == null) return;
        try {
            speechService.cancel();
        } catch (RuntimeException | LinkageError ignored) {
            // releaseNativeResources still gets a chance to shut down the worker.
        }
    }

    private void cancelListeningTimeout() {
        if (listeningTimeout == null) return;
        mainHandler.removeCallbacks(listeningTimeout);
        listeningTimeout = null;
    }

    private static void closeModelQuietly(final Model model) {
        if (model == null) return;
        try {
            model.close();
        } catch (RuntimeException | LinkageError ignored) {
            // Native initialization may have failed before the model became fully usable.
        }
    }

    private final class Listener implements RecognitionListener {
        private final int session;

        Listener(final int session) {
            this.session = session;
        }

        @Override
        public void onResult(final String hypothesis) {
            if (session == generation && state != State.IDLE) addSegment(hypothesis);
        }

        @Override
        public void onFinalResult(final String hypothesis) {
            finish(session, hypothesis);
        }

        @Override
        public void onPartialResult(final String hypothesis) {
            // Partial hypotheses are intentionally neither stored nor logged.
        }

        @Override
        public void onError(final Exception exception) {
            fail(session, R.string.offline_voice_microphone_error);
        }

        @Override
        public void onTimeout() {
            stopForResult(session);
        }
    }
}
