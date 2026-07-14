// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.app.Application
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Looper
import android.view.View
import android.view.WindowManager
import android.widget.Button
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class ProcessTextDecryptActivityTest {
    private lateinit var backendField: java.lang.reflect.Field
    private var originalBackend: Any? = null

    @Before
    fun isolateDecryptRuntime() {
        backendField = SecureDecryptRuntime::class.java.getDeclaredField("backend").apply {
            isAccessible = true
        }
        originalBackend = backendField.get(null)
        backendField.set(null, null)
    }

    @After
    fun restoreDecryptRuntime() {
        backendField.set(null, originalBackend)
    }

    @Test
    fun viewerIsSecureWipesTransferredBytesAndNeverReturnsPlaintext() {
        val plaintextBytes = "viewer-only test plaintext".encodeToByteArray()
        val parsedLatch = CountDownLatch(1)
        val decryptedLatch = CountDownLatch(1)
        val leaseClosed = AtomicBoolean(false)
        val leaseDisplayed = AtomicBoolean(false)
        SecureDecryptRuntime.install(
            object : SecureDecryptBackend {
                override fun parse(parts: List<String>): ParseResult {
                    parsedLatch.countDown()
                    return ParseResult.Success(object : ParsedCiphertext {
                        override fun close() = Unit
                    })
                }

                override fun decrypt(
                    host: FragmentActivity,
                    parsed: ParsedCiphertext,
                    callback: (DecryptResult) -> Unit,
                ): DecryptOperation {
                    callback(
                        DecryptResult.Success(
                            DecryptedMessage(
                                plaintext = WipeablePlaintext.takeOwnership(plaintextBytes),
                                localContactLabel = "Local test contact",
                                contactStatus = DecryptedContactStatus.VERIFIED,
                                replyToken = null,
                                displayLease = object : SecureDisplayLease {
                                    override fun markDisplayed() {
                                        leaseDisplayed.set(true)
                                    }

                                    override fun close() {
                                        leaseClosed.set(true)
                                    }
                                },
                            ),
                        ),
                    )
                    decryptedLatch.countDown()
                    return DecryptOperation { }
                }

                override fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean = false

                override fun canDisplayPlaintext(): Boolean = true
            },
        )

        val sourceIntent = Intent(Intent.ACTION_PROCESS_TEXT).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_PROCESS_TEXT, "CB1:AA")
        }
        val controller = Robolectric.buildActivity(ProcessTextDecryptActivity::class.java, sourceIntent)
            .create()
            .start()
            .resume()
            .visible()
        val activity = controller.get()
        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val retainedCiphertext = "CB1:clipboard-must-remain-ciphertext"
        clipboard.setPrimaryClip(ClipData("", arrayOf("text/plain"), ClipData.Item(retainedCiphertext)))

        assertFalse(parsedLatch.await(100, TimeUnit.MILLISECONDS))
        activity.findViewById<Button>(R.id.secure_decrypt_confirm_button).performClick()
        assertTrue(parsedLatch.await(5, TimeUnit.SECONDS))
        assertTrue(awaitWithMainLooper(decryptedLatch))
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(
            activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
        )
        assertFalse(sourceIntent.hasExtra(Intent.EXTRA_PROCESS_TEXT))
        assertTrue(plaintextBytes.all { it == 0.toByte() })
        assertFalse(leaseDisplayed.get())
        val plaintextView = activity.findViewById<View>(R.id.secure_viewer_plaintext)
        val width = 480
        val height = 240
        plaintextView.measure(
            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY),
        )
        plaintextView.layout(0, 0, width, height)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        plaintextView.draw(Canvas(bitmap))
        assertTrue(leaseDisplayed.get())
        bitmap.recycle()
        assertEquals(Activity.RESULT_CANCELED, shadowOf(activity).resultCode)
        assertNull(shadowOf(activity).resultIntent)
        val retainedClipboardText = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
        assertEquals(retainedCiphertext, retainedClipboardText)
        assertFalse(retainedClipboardText.orEmpty().contains("viewer-only test plaintext"))

        controller.pause()
        assertTrue(leaseClosed.get())
        controller.stop().destroy()
    }

    @Test
    fun firstDrawFailsClosedWhenVaultWasLockedAfterDecrypt() {
        val decryptedLatch = CountDownLatch(1)
        val leaseDisplayed = AtomicBoolean(false)
        val leaseClosed = AtomicBoolean(false)
        SecureDecryptRuntime.install(
            object : SecureDecryptBackend {
                override fun parse(parts: List<String>): ParseResult =
                    ParseResult.Success(object : ParsedCiphertext {
                        override fun close() = Unit
                    })

                override fun decrypt(
                    host: FragmentActivity,
                    parsed: ParsedCiphertext,
                    callback: (DecryptResult) -> Unit,
                ): DecryptOperation {
                    callback(
                        DecryptResult.Success(
                            DecryptedMessage(
                                plaintext = WipeablePlaintext.takeOwnership(
                                    "must-not-render".encodeToByteArray(),
                                ),
                                localContactLabel = "Local test contact",
                                contactStatus = DecryptedContactStatus.VERIFIED,
                                replyToken = null,
                                displayLease = object : SecureDisplayLease {
                                    override fun markDisplayed() {
                                        leaseDisplayed.set(true)
                                    }

                                    override fun close() {
                                        leaseClosed.set(true)
                                    }
                                },
                            ),
                        ),
                    )
                    decryptedLatch.countDown()
                    return DecryptOperation { }
                }

                override fun canDisplayPlaintext(): Boolean = false

                override fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean = false
            },
        )

        val controller = processTextController()
        val activity = controller.get()
        activity.findViewById<Button>(R.id.secure_decrypt_confirm_button).performClick()
        assertTrue(awaitWithMainLooper(decryptedLatch))

        drawPlaintextView(activity)
        assertFalse(leaseDisplayed.get())
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(activity.isFinishing)
        assertTrue(leaseClosed.get())

        controller.pause().stop().destroy()
    }

    @Test
    fun pauseCancelsDecryptInFlightAndFinishesViewer() {
        val decryptStarted = CountDownLatch(1)
        val decryptCancelled = AtomicBoolean(false)
        val parsedClosed = AtomicBoolean(false)
        SecureDecryptRuntime.install(
            object : SecureDecryptBackend {
                override fun parse(parts: List<String>): ParseResult =
                    ParseResult.Success(object : ParsedCiphertext {
                        override fun close() {
                            parsedClosed.set(true)
                        }
                    })

                override fun decrypt(
                    host: FragmentActivity,
                    parsed: ParsedCiphertext,
                    callback: (DecryptResult) -> Unit,
                ): DecryptOperation {
                    decryptStarted.countDown()
                    return DecryptOperation { decryptCancelled.set(true) }
                }

                override fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean = false
            },
        )

        val controller = processTextController()
        val activity = controller.get()
        activity.findViewById<Button>(R.id.secure_decrypt_confirm_button).performClick()
        assertTrue(awaitWithMainLooper(decryptStarted))

        controller.pause()

        assertTrue(activity.isFinishing)
        assertTrue(decryptCancelled.get())
        assertTrue(parsedClosed.get())
        controller.stop().destroy()
    }

    @Test
    fun pauseCancelsParseInFlightAndFinishesViewer() {
        val parseStarted = CountDownLatch(1)
        val parseInterrupted = CountDownLatch(1)
        SecureDecryptRuntime.install(
            object : SecureDecryptBackend {
                override fun parse(parts: List<String>): ParseResult {
                    parseStarted.countDown()
                    try {
                        CountDownLatch(1).await()
                    } catch (_: InterruptedException) {
                        parseInterrupted.countDown()
                        Thread.currentThread().interrupt()
                    }
                    return ParseResult.Failure(ParseFailureReason.INTERNAL_ERROR)
                }

                override fun decrypt(
                    host: FragmentActivity,
                    parsed: ParsedCiphertext,
                    callback: (DecryptResult) -> Unit,
                ): DecryptOperation = DecryptOperation { }

                override fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean = false
            },
        )

        val controller = processTextController()
        val activity = controller.get()
        activity.findViewById<Button>(R.id.secure_decrypt_confirm_button).performClick()
        assertTrue(parseStarted.await(5, TimeUnit.SECONDS))

        controller.pause()

        assertTrue(activity.isFinishing)
        assertTrue(parseInterrupted.await(5, TimeUnit.SECONDS))
        controller.stop().destroy()
    }

    @Test
    fun pauseAllowsOnlyActiveLegacyCredentialTransition() {
        val credentialCancelled = AtomicBoolean(false)
        SecureDecryptRuntime.install(
            object : SecureDecryptBackend {
                override fun parse(parts: List<String>): ParseResult =
                    ParseResult.Failure(ParseFailureReason.INTERNAL_ERROR)

                override fun decrypt(
                    host: FragmentActivity,
                    parsed: ParsedCiphertext,
                    callback: (DecryptResult) -> Unit,
                ): DecryptOperation = DecryptOperation { }

                override fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean = false
            },
        )
        val controller = processTextController()
        val activity = controller.get()
        SecureMessageViewerActivity::class.java
            .getDeclaredField("pendingLegacyCredentialResult")
            .apply { isAccessible = true }
            .set(activity) { authenticated: Boolean -> credentialCancelled.set(!authenticated) }

        controller.pause().stop()

        assertFalse(activity.isFinishing)
        controller.destroy()
        assertTrue(credentialCancelled.get())
    }

    private fun processTextController() = Robolectric.buildActivity(
        ProcessTextDecryptActivity::class.java,
        Intent(Intent.ACTION_PROCESS_TEXT).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_PROCESS_TEXT, "CB1:AA")
        },
    ).create().start().resume().visible()

    private fun drawPlaintextView(activity: Activity) {
        val plaintextView = activity.findViewById<View>(R.id.secure_viewer_plaintext)
        val width = 480
        val height = 240
        plaintextView.measure(
            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY),
        )
        plaintextView.layout(0, 0, width, height)
        Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).also { bitmap ->
            plaintextView.draw(Canvas(bitmap))
            bitmap.recycle()
        }
    }

    private fun awaitWithMainLooper(latch: CountDownLatch): Boolean {
        repeat(50) {
            shadowOf(Looper.getMainLooper()).idle()
            if (latch.await(100, TimeUnit.MILLISECONDS)) return true
        }
        return false
    }
}
