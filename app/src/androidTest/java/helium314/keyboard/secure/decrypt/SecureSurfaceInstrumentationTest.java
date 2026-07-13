// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Instrumentation;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import androidx.fragment.app.FragmentActivity;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import helium314.keyboard.latin.R;
import helium314.keyboard.secure.testfixture.ProcessTextHostActivity;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.junit.Test;

public final class SecureSurfaceInstrumentationTest {
    private static final long ACTIVITY_TIMEOUT_MILLIS = 8_000L;
    private static final String HOST_FIELD_SENTINEL = "host-field-must-remain-unchanged";
    private static final String SELECTED_CIPHERTEXT_SENTINEL = "CB1:SelectedCiphertextSentinel_123";
    private static final String CLIPBOARD_CIPHERTEXT_SENTINEL = "CB1:ClipboardCiphertextSentinel_456";
    private static final String PLAINTEXT_SENTINEL = "decrypted plaintext must stay in secure viewer";

    @Test
    public void processTextReturnsNoPlaintextAndBackgroundWipesViewer() throws Exception {
        keepDesugarSynchronizedCollectionsReachable();
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Instrumentation.ActivityMonitor monitor = instrumentation.addMonitor(
            ProcessTextDecryptActivity.class.getName(),
            null,
            false
        );
        SuccessfulTestBackend fakeBackend = new SuccessfulTestBackend(
            PLAINTEXT_SENTINEL.getBytes(StandardCharsets.UTF_8)
        );
        Field backendField = SecureDecryptRuntime.class.getDeclaredField("backend");
        backendField.setAccessible(true);
        Object originalBackend = backendField.get(null);
        backendField.set(null, fakeBackend);

        Intent hostIntent = new Intent(targetContext, ProcessTextHostActivity.class);
        hostIntent.putExtra(ProcessTextHostActivity.EXTRA_HOST_TEXT, HOST_FIELD_SENTINEL);
        AtomicReference<ProcessTextHostActivity> host = new AtomicReference<>();
        AtomicReference<ProcessTextDecryptActivity> launched = new AtomicReference<>();
        AtomicReference<char[]> visibleChars = new AtomicReference<>();
        try (ActivityScenario<ProcessTextHostActivity> hostScenario = ActivityScenario.launch(hostIntent)) {
            hostScenario.onActivity(activity -> {
                host.set(activity);
                Intent processIntent = new Intent(Intent.ACTION_PROCESS_TEXT);
                processIntent.setClass(targetContext, ProcessTextDecryptActivity.class);
                processIntent.setType("text/plain");
                processIntent.putExtra(Intent.EXTRA_PROCESS_TEXT, SELECTED_CIPHERTEXT_SENTINEL);
                processIntent.putExtra(Intent.EXTRA_PROCESS_TEXT_READONLY, true);
                activity.launchProcessText(processIntent);
            });

            Activity monitored = instrumentation.waitForMonitorWithTimeout(monitor, ACTIVITY_TIMEOUT_MILLIS);
            assertTrue("PROCESS_TEXT Activity was not launched", monitored instanceof ProcessTextDecryptActivity);
            ProcessTextDecryptActivity viewer = (ProcessTextDecryptActivity) monitored;
            launched.set(viewer);
            instrumentation.runOnMainSync(() -> {
                assertSecureWindow(viewer);
                assertFalse(viewer.getIntent().hasExtra(Intent.EXTRA_PROCESS_TEXT));
                assertFalse(viewer.getIntent().hasExtra(Intent.EXTRA_PROCESS_TEXT_READONLY));
                viewer.<Button>findViewById(R.id.secure_decrypt_confirm_button).performClick();
            });

            waitUntil("test plaintext was not displayed", fakeBackend.displayMarked::get);
            instrumentation.runOnMainSync(() -> {
                try {
                    View plaintextSurface = extractPlaintextView(viewer);
                    assertEquals(
                        View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS,
                        plaintextSurface.getImportantForAccessibility()
                    );
                    assertNull(plaintextSurface.getContentDescription());
                    assertFalse(plaintextSurface.isFocusable());
                    assertFalse(plaintextSurface.isLongClickable());
                    visibleChars.set(extractVisiblePlaintextChars(viewer));
                } catch (ReflectiveOperationException exception) {
                    throw new AssertionError(exception);
                }
                assertArrayEquals(PLAINTEXT_SENTINEL.toCharArray(), visibleChars.get());
                assertTrue("viewer task could not be backgrounded", viewer.moveTaskToBack(true));
            });

            waitUntil("secure display lease was not closed", fakeBackend.displayClosed::get);
            bringTaskToFront(targetContext, host.get().getTaskId());
            assertTrue(
                "PROCESS_TEXT did not return after viewer entered background",
                host.get().getResultLatch().await(ACTIVITY_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            );
            instrumentation.waitForIdleSync();

            assertEquals(Activity.RESULT_CANCELED, host.get().getReturnedResultCode());
            assertNull(host.get().getReturnedData());
            hostScenario.onActivity(activity -> {
                String hostText = activity.getEditor().getText().toString();
                assertEquals(HOST_FIELD_SENTINEL, hostText);
                assertFalse(hostText.contains(PLAINTEXT_SENTINEL));
            });
            assertTrue(fakeBackend.parsedClosed.get());
            assertAllZero(fakeBackend.ownedUtf8);
            assertAllZero(visibleChars.get());
            assertTrue(isViewerPlaintextCleared(viewer));
            assertTrue(viewer.isFinishing() || viewer.isDestroyed());
        } finally {
            ProcessTextDecryptActivity activity = launched.get();
            if (activity != null) {
                instrumentation.runOnMainSync(() -> {
                    if (!activity.isFinishing() && !activity.isDestroyed()) activity.finish();
                });
            }
            backendField.set(null, originalBackend);
            instrumentation.removeMonitor(monitor);
        }
    }

    @Test
    public void clipboardFallbackReadsOnlyAfterClickAndDoesNotReplaceClipboard() {
        keepDesugarSynchronizedCollectionsReachable();
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Instrumentation.ActivityMonitor monitor = instrumentation.addMonitor(
            SecureMessageViewerActivity.class.getName(),
            null,
            false
        );
        AtomicReference<ClipData> originalClip = new AtomicReference<>();
        AtomicReference<SecureMessageViewerActivity> viewer = new AtomicReference<>();
        try (ActivityScenario<CiphertextClipboardActivity> scenario = ActivityScenario.launch(
            new Intent(targetContext, CiphertextClipboardActivity.class)
        )) {
            scenario.onActivity(activity -> {
                ClipboardManager clipboard =
                    (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                originalClip.set(clipboard.getPrimaryClip());
                ClipData ciphertextClip = ClipData.newPlainText("", CLIPBOARD_CIPHERTEXT_SENTINEL);
                clipboard.setPrimaryClip(ciphertextClip);
                assertSecureWindow(activity);
                List<Button> buttons = findDescendants(activity, Button.class);
                Button action = null;
                for (Button candidate : buttons) {
                    if (candidate.getText().toString().equals(
                        activity.getString(R.string.secure_clipboard_decrypt_action)
                    )) {
                        assertNull("duplicate clipboard decrypt action", action);
                        action = candidate;
                    }
                }
                assertNotNull("clipboard decrypt action missing", action);
                action.performClick();
            });

            Activity monitored = instrumentation.waitForMonitorWithTimeout(monitor, ACTIVITY_TIMEOUT_MILLIS);
            assertTrue("clipboard fallback did not open secure viewer", monitored instanceof SecureMessageViewerActivity);
            SecureMessageViewerActivity activity = (SecureMessageViewerActivity) monitored;
            viewer.set(activity);
            waitUntil("secure viewer did not receive window focus", activity::hasWindowFocus);
            instrumentation.runOnMainSync(() -> {
                ClipboardManager clipboard =
                    (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData retainedClip = clipboard.getPrimaryClip();
                String retained = retainedClip != null && retainedClip.getItemCount() == 1
                    ? String.valueOf(retainedClip.getItemAt(0).getText())
                    : null;
                assertEquals(CLIPBOARD_CIPHERTEXT_SENTINEL, retained);
                assertFalse(retained != null && retained.contains(PLAINTEXT_SENTINEL));
                assertSecureWindow(activity);
                if (originalClip.get() == null) clipboard.clearPrimaryClip();
                else clipboard.setPrimaryClip(originalClip.get());
                activity.finish();
            });
        } finally {
            SecureMessageViewerActivity activity = viewer.get();
            if (activity != null) {
                instrumentation.runOnMainSync(() -> {
                    if (!activity.isFinishing() && !activity.isDestroyed()) activity.finish();
                });
            }
            instrumentation.removeMonitor(monitor);
        }
    }

    private static void keepDesugarSynchronizedCollectionsReachable() {
        Map<String, String> synchronizedMap = Collections.synchronizedMap(new HashMap<>());
        synchronizedMap.put("probe", "value");
        assertEquals("value", synchronizedMap.remove("probe"));
    }

    private static void assertSecureWindow(Activity activity) {
        assertTrue(
            (activity.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0
        );
    }

    private static void bringTaskToFront(Context context, int taskId) {
        ActivityManager activityManager = context.getSystemService(ActivityManager.class);
        assertNotNull(activityManager);
        for (ActivityManager.AppTask task : activityManager.getAppTasks()) {
            if (task.getTaskInfo().taskId == taskId) {
                task.moveToFront();
                return;
            }
        }
        throw new AssertionError("host task not found");
    }

    private static char[] extractVisiblePlaintextChars(SecureMessageViewerActivity activity)
        throws ReflectiveOperationException {
        View plaintextView = extractPlaintextView(activity);
        Field secureTextField = plaintextView.getClass().getDeclaredField("secureText");
        secureTextField.setAccessible(true);
        Object secureText = secureTextField.get(plaintextView);
        assertNotNull(secureText);
        Field charsField = secureText.getClass().getDeclaredField("chars");
        charsField.setAccessible(true);
        return (char[]) charsField.get(secureText);
    }

    private static View extractPlaintextView(SecureMessageViewerActivity activity)
        throws ReflectiveOperationException {
        Field plaintextViewField = SecureMessageViewerActivity.class.getDeclaredField("plaintextView");
        plaintextViewField.setAccessible(true);
        return (View) plaintextViewField.get(activity);
    }

    private static boolean isViewerPlaintextCleared(SecureMessageViewerActivity activity)
        throws ReflectiveOperationException {
        Field plaintextViewField = SecureMessageViewerActivity.class.getDeclaredField("plaintextView");
        plaintextViewField.setAccessible(true);
        Object plaintextView = plaintextViewField.get(activity);
        Field secureTextField = plaintextView.getClass().getDeclaredField("secureText");
        secureTextField.setAccessible(true);
        return secureTextField.get(plaintextView) == null;
    }

    private static <T extends View> List<T> findDescendants(Activity activity, Class<T> type) {
        List<T> matches = new ArrayList<>();
        ArrayDeque<View> pending = new ArrayDeque<>();
        pending.add(activity.findViewById(android.R.id.content));
        while (!pending.isEmpty()) {
            View view = pending.removeFirst();
            if (type.isInstance(view)) matches.add(type.cast(view));
            if (view instanceof ViewGroup) {
                ViewGroup group = (ViewGroup) view;
                for (int index = 0; index < group.getChildCount(); index++) {
                    pending.add(group.getChildAt(index));
                }
            }
        }
        return matches;
    }

    private static void waitUntil(String message, BooleanSupplier condition) {
        long deadline = SystemClock.uptimeMillis() + ACTIVITY_TIMEOUT_MILLIS;
        while (!condition.getAsBoolean() && SystemClock.uptimeMillis() < deadline) {
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            SystemClock.sleep(25);
        }
        assertTrue(message, condition.getAsBoolean());
    }

    private static void assertAllZero(byte[] bytes) {
        assertNotNull(bytes);
        for (byte value : bytes) assertEquals(0, value);
    }

    private static void assertAllZero(char[] chars) {
        assertNotNull(chars);
        for (char value : chars) assertEquals(0, value);
    }

    private static final class SuccessfulTestBackend implements SecureDecryptBackend {
        private final byte[] ownedUtf8;
        private final AtomicBoolean parsedClosed = new AtomicBoolean(false);
        private final AtomicBoolean displayMarked = new AtomicBoolean(false);
        private final AtomicBoolean displayClosed = new AtomicBoolean(false);

        SuccessfulTestBackend(byte[] plaintext) {
            ownedUtf8 = plaintext;
        }

        @Override
        public ParseResult parse(List<String> parts) {
            return new ParseResult.Success(() -> parsedClosed.set(true));
        }

        @Override
        public DecryptOperation decrypt(
            FragmentActivity host,
            ParsedCiphertext parsed,
            Function1<? super DecryptResult, Unit> callback
        ) {
            SecureDisplayLease lease = new SecureDisplayLease() {
                @Override
                public void markDisplayed() {
                    displayMarked.set(true);
                }

                @Override
                public void close() {
                    displayClosed.set(true);
                }
            };
            DecryptedMessage message = new DecryptedMessage(
                WipeablePlaintext.Companion.takeOwnership(ownedUtf8),
                "Instrumentation contact",
                DecryptedContactStatus.VERIFIED,
                null,
                lease
            );
            callback.invoke(new DecryptResult.Success(message));
            return () -> { };
        }

        @Override
        public boolean openSecureReply(Activity host, SecureReplyToken token) {
            return false;
        }

        @Override
        public long getViewerTimeoutMillis() {
            return 60_000L;
        }
    }
}
