// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R

/** Explicit fallback for hosts that do not expose selected text through InputConnection. */
class CiphertextClipboardActivity : FragmentActivity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(24))
        }
        content.addView(TextView(this).apply {
            setText(R.string.secure_clipboard_decrypt_title)
            textSize = 24f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        content.addView(TextView(this).apply {
            setText(R.string.secure_clipboard_decrypt_description)
            textSize = 16f
        }, margins(12))
        status = TextView(this)
        content.addView(status, margins(12))
        content.addView(Button(this).apply {
            setText(R.string.secure_clipboard_decrypt_action)
            setOnClickListener { readCiphertextAfterConfirmation() }
        }, margins(20))
        content.addView(Button(this).apply {
            setText(android.R.string.cancel)
            setOnClickListener { finish() }
        }, margins(8))
        setContentView(content)
    }

    private fun readCiphertextAfterConfirmation() {
        val selected = try {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            val clip = clipboard?.primaryClip
            if (clip != null && clip.itemCount == 1) {
                CiphertextSelection.copyBoundedUntrustedText(clip.getItemAt(0).text)
            } else {
                null
            }
        } catch (_: RuntimeException) {
            null
        }
        when (selected?.let(CiphertextSelection::parse)) {
            is CiphertextSelection.Result.Valid -> {
                runCatching {
                    startActivity(SecureMessageViewerActivity.createCiphertextIntent(this, selected))
                }.onSuccess {
                    finish()
                }.onFailure {
                    status.setText(R.string.secure_clipboard_decrypt_invalid)
                }
            }
            else -> status.setText(R.string.secure_clipboard_decrypt_invalid)
        }
    }

    private fun margins(top: Int) =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(top)
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
