// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securekeyboard.runtime.SecureViewerTimeout
import org.cipherboard.securekeyboard.runtime.VaultPolicyPreferences
import org.cipherboard.securekeyboard.runtime.ViewerTimeoutPreferences
import org.cipherboard.securestorage.VaultLockPolicy

class VaultSettingsActivity : FragmentActivity() {
    private lateinit var runtime: SecureKeyboardRuntime

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        runtime = SecureKeyboardRuntime.get()
        setContentView(buildContent())
    }

    private fun buildContent(): View {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(24))
        }
        content.addView(heading(R.string.cipherboard_vault_settings_title, 24f))
        content.addView(body(R.string.cipherboard_vault_settings_description), margins(top = 8))
        content.addView(heading(R.string.cipherboard_vault_settings_timeout, 18f), margins(top = 24))

        val options = RadioGroup(this).apply { orientation = RadioGroup.VERTICAL }
        val selected = VaultPolicyPreferences.read(this)
        POLICY_OPTIONS.forEach { option ->
            options.addView(RadioButton(this).apply {
                id = View.generateViewId()
                tag = option.policy
                setText(option.label)
                isChecked = option.policy == selected
            })
        }
        options.setOnCheckedChangeListener { group, checkedId ->
            val selectedPolicy = group.findViewById<RadioButton>(checkedId)?.tag as? VaultLockPolicy
                ?: return@setOnCheckedChangeListener
            if (VaultPolicyPreferences.write(this, selectedPolicy)) {
                runtime.lockPolicy = selectedPolicy
            } else {
                Toast.makeText(this, R.string.cipherboard_vault_settings_save_failed, Toast.LENGTH_SHORT).show()
            }
        }
        content.addView(options, margins(top = 8))

        content.addView(heading(R.string.cipherboard_viewer_timeout, 18f), margins(top = 24))
        content.addView(body(R.string.cipherboard_viewer_timeout_description), margins(top = 6))
        val viewerOptions = RadioGroup(this).apply { orientation = RadioGroup.VERTICAL }
        val selectedViewerTimeout = ViewerTimeoutPreferences.read(this)
        VIEWER_TIMEOUT_OPTIONS.forEach { option ->
            viewerOptions.addView(RadioButton(this).apply {
                id = View.generateViewId()
                tag = option.timeout
                setText(option.label)
                isChecked = option.timeout == selectedViewerTimeout
            })
        }
        viewerOptions.setOnCheckedChangeListener { group, checkedId ->
            val timeout = group.findViewById<RadioButton>(checkedId)?.tag as? SecureViewerTimeout
                ?: return@setOnCheckedChangeListener
            if (!ViewerTimeoutPreferences.write(this, timeout)) {
                Toast.makeText(this, R.string.cipherboard_vault_settings_save_failed, Toast.LENGTH_SHORT).show()
            }
        }
        content.addView(viewerOptions, margins(top = 8))

        content.addView(body(R.string.cipherboard_vault_settings_lock_boundaries), margins(top = 20))
        content.addView(Button(this).apply {
            setText(R.string.cipherboard_vault_settings_lock_now)
            setOnClickListener {
                runtime.lockVault()
                Toast.makeText(this@VaultSettingsActivity, R.string.cipherboard_vault_settings_locked, Toast.LENGTH_SHORT).show()
                finish()
            }
        }, margins(top = 24))
        content.addView(Button(this).apply {
            setText(R.string.cipherboard_pairing_close)
            setOnClickListener { finish() }
        }, margins(top = 8))

        return ScrollView(this).apply {
            isFillViewport = true
            addView(content, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))
        }
    }

    private fun heading(text: Int, size: Float) = TextView(this).apply {
        setText(text)
        textSize = size
        setTypeface(typeface, android.graphics.Typeface.BOLD)
    }

    private fun body(text: Int) = TextView(this).apply {
        setText(text)
        textSize = 16f
    }

    private fun margins(top: Int = 0) =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(top)
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private data class PolicyOption(val policy: VaultLockPolicy, val label: Int)
    private data class ViewerTimeoutOption(val timeout: SecureViewerTimeout, val label: Int)

    private companion object {
        val POLICY_OPTIONS = listOf(
            PolicyOption(VaultLockPolicy.IMMEDIATE, R.string.cipherboard_vault_settings_immediate),
            PolicyOption(VaultLockPolicy.THIRTY_SECONDS, R.string.cipherboard_vault_settings_30_seconds),
            PolicyOption(VaultLockPolicy.ONE_MINUTE, R.string.cipherboard_vault_settings_1_minute),
            PolicyOption(VaultLockPolicy.FIVE_MINUTES, R.string.cipherboard_vault_settings_5_minutes),
        )
        val VIEWER_TIMEOUT_OPTIONS = listOf(
            ViewerTimeoutOption(SecureViewerTimeout.FIFTEEN_SECONDS, R.string.cipherboard_viewer_15_seconds),
            ViewerTimeoutOption(SecureViewerTimeout.THIRTY_SECONDS, R.string.cipherboard_viewer_30_seconds),
            ViewerTimeoutOption(SecureViewerTimeout.ONE_MINUTE, R.string.cipherboard_viewer_1_minute),
            ViewerTimeoutOption(SecureViewerTimeout.FIVE_MINUTES, R.string.cipherboard_viewer_5_minutes),
        )
    }
}
