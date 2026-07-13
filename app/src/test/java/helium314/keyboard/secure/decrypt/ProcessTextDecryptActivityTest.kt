// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.app.Application
import android.app.Activity
import android.content.Intent
import android.os.Looper
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
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class ProcessTextDecryptActivityTest {
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
        assertTrue(leaseDisplayed.get())
        assertEquals(Activity.RESULT_CANCELED, shadowOf(activity).resultCode)
        assertNull(shadowOf(activity).resultIntent)

        controller.pause()
        assertTrue(leaseClosed.get())
        controller.stop().destroy()
    }

    private fun awaitWithMainLooper(latch: CountDownLatch): Boolean {
        repeat(50) {
            shadowOf(Looper.getMainLooper()).idle()
            if (latch.await(100, TimeUnit.MILLISECONDS)) return true
        }
        return false
    }
}
