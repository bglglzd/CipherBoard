// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.app.Activity
import android.app.KeyguardManager
import android.app.assist.AssistContent
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securekeyboard.runtime.VaultUnlockAction

/** Non-exported authentication bridge. It never receives, renders or persists a plaintext draft. */
class SecureVaultUnlockActivity : FragmentActivity() {
    private lateinit var runtime: SecureKeyboardRuntime
    private lateinit var status: TextView
    private var pendingPromptAction: VaultUnlockAction.AuthenticationRequired? = null
    private var biometricPrompt: BiometricPrompt? = null

    private val credentialLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val action = pendingPromptAction.also { pendingPromptAction = null } ?: return@registerForActivityResult
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult finish()
        runCatching { runtime.completePromptAuthentication(action) }
            .onSuccess(::handleUnlockAction)
            .onFailure { failAndFinish() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        status = TextView(this).apply {
            gravity = Gravity.CENTER
            setPadding(dp(24), dp(24), dp(24), dp(24))
            setText(R.string.embedded_secure_unlocking)
            isSaveEnabled = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            }
        }
        ViewCompat.setOnApplyWindowInsetsListener(status) { view, insets ->
            val safe = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            view.setPadding(dp(24) + safe.left, dp(24) + safe.top, dp(24) + safe.right, dp(24) + safe.bottom)
            insets
        }
        setContentView(status)
        runtime = SecureKeyboardRuntime.get()
        if (runtime.isVaultUnlocked) {
            finish()
        } else {
            requestUnlock()
        }
    }

    override fun onProvideAssistData(data: Bundle) = data.clear()

    override fun onProvideAssistContent(outContent: AssistContent) = Unit

    private fun requestUnlock() {
        runCatching { runtime.prepareUnlock() }
            .onSuccess(::handleUnlockAction)
            .onFailure { failAndFinish() }
    }

    private fun handleUnlockAction(action: VaultUnlockAction) {
        when (action) {
            is VaultUnlockAction.Unlocked -> finish()
            is VaultUnlockAction.AuthenticationRequired -> authenticate(action)
            is VaultUnlockAction.CryptoObjectAuthenticationRequired -> authenticate(action)
            is VaultUnlockAction.KeyInvalidated -> failAndFinish()
        }
    }

    private fun authenticate(action: VaultUnlockAction.AuthenticationRequired) {
        if (action.requiresLegacyConfirmCredential) {
            val intent = getSystemService(KeyguardManager::class.java)?.createConfirmDeviceCredentialIntent(
                getString(R.string.secure_unlock_vault),
                getString(R.string.secure_unlock_vault_description),
            ) ?: return failAndFinish()
            pendingPromptAction = action
            credentialLauncher.launch(intent)
            return
        }
        val prompt = newBiometricPrompt {
            runCatching { runtime.completePromptAuthentication(action) }
                .onSuccess(::handleUnlockAction)
                .onFailure { failAndFinish() }
        }
        biometricPrompt = prompt
        prompt.authenticate(promptInfo(action.allowedAuthenticators))
    }

    private fun authenticate(action: VaultUnlockAction.CryptoObjectAuthenticationRequired) {
        val cryptoObject = action.cryptoObject as? BiometricPrompt.CryptoObject ?: return failAndFinish()
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject ?: return failAndFinish()
                    runCatching { runtime.completeCryptoObjectAuthentication(action, authenticated) }
                        .onSuccess(::handleUnlockAction)
                        .onFailure { failAndFinish() }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = finish()
            },
        )
        biometricPrompt = prompt
        prompt.authenticate(promptInfo(action.allowedAuthenticators), cryptoObject)
    }

    private fun newBiometricPrompt(onSuccess: () -> Unit): BiometricPrompt = BiometricPrompt(
        this,
        ContextCompat.getMainExecutor(this),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = finish()
        },
    )

    private fun promptInfo(allowedAuthenticators: Int): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.secure_unlock_vault))
            .setSubtitle(getString(R.string.secure_unlock_vault_description))
            .setAllowedAuthenticators(allowedAuthenticators)
        if (allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
            builder.setNegativeButtonText(getString(android.R.string.cancel))
        }
        return builder.build()
    }

    private fun failAndFinish() {
        status.setText(R.string.embedded_secure_unlock_failed)
        status.postDelayed({ finish() }, FAILURE_VISIBLE_MILLIS)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val FAILURE_VISIBLE_MILLIS = 900L
    }
}
