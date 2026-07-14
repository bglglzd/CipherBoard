// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.app.Activity
import android.app.KeyguardManager
import android.app.assist.AssistContent
import android.content.ComponentCallbacks2
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import helium314.keyboard.latin.R
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future

/**
 * Non-exported secure viewer. It accepts ciphertext only and performs decryption in this window.
 * [ProcessTextDecryptActivity] exposes the same viewer through Android's PROCESS_TEXT action.
 */
open class SecureMessageViewerActivity : FragmentActivity(), LegacyDeviceCredentialHost {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val parserExecutor: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "cipherboard-envelope-parser").apply { isDaemon = true }
    }

    private lateinit var headingView: TextView
    private lateinit var contactView: TextView
    private lateinit var statusView: TextView
    private lateinit var progressView: ProgressBar
    private lateinit var plaintextView: SecurePlaintextView
    private lateinit var decryptButton: Button
    private lateinit var replyButton: Button

    private var parseFuture: Future<*>? = null
    private var parsedCiphertext: ParsedCiphertext? = null
    private var decryptOperation: DecryptOperation? = null
    private var decryptedMessage: DecryptedMessage? = null
    private var pendingConfirmationCiphertext: String? = null
    private var generation = 0L
    private var isForeground = false
    private var isPlaintextVisible = false
    private var plaintextMarkedDisplayed = false
    private var pendingLegacyCredentialResult: ((Boolean) -> Unit)? = null

    private val legacyCredentialLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val callback = pendingLegacyCredentialResult.also { pendingLegacyCredentialResult = null }
            ?: return@registerForActivityResult
        callback(result.resultCode == Activity.RESULT_OK)
    }

    private val timeoutAction = Runnable { hideAndFinish() }
    private val renderTimeoutAction = Runnable {
        if (isPlaintextVisible && !plaintextMarkedDisplayed) hideAndFinish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        configureSecureWindow()
        setResult(RESULT_CANCELED)
        buildContentView()

        val incoming = try {
            readCiphertext(intent)
        } catch (_: RuntimeException) {
            null
        } finally {
            runCatching { clearCiphertextExtra(intent) }
        }
        if (incoming == null) {
            showFailure(R.string.secure_decrypt_invalid_selection)
            return
        }
        if (requiresExplicitDecryptConfirmation) {
            pendingConfirmationCiphertext = incoming
            statusView.setText(R.string.secure_decrypt_confirmation_required)
            progressView.visibility = View.GONE
            decryptButton.visibility = View.VISIBLE
        } else {
            beginParsing(incoming)
        }
    }

    protected open val requiresExplicitDecryptConfirmation: Boolean = false

    /** The base activity is only reachable explicitly from this app. */
    protected open fun readCiphertext(sourceIntent: Intent): String? {
        val expectedAction = "${packageName}.action.VIEW_CIPHERTEXT"
        if (sourceIntent.action != expectedAction) return null
        return CiphertextSelection.readBoundedTextExtra(sourceIntent, EXTRA_CIPHERTEXT)
    }

    protected open fun clearCiphertextExtra(sourceIntent: Intent) {
        sourceIntent.removeExtra(EXTRA_CIPHERTEXT)
    }

    override fun onResume() {
        super.onResume()
        isForeground = true
        if (isPlaintextVisible && plaintextMarkedDisplayed) scheduleTimeout()
    }

    override fun onPause() {
        isForeground = false
        if (hasSensitiveWork() && !isLegacyCredentialTransitionActive()) hideAndFinish()
        super.onPause()
    }

    override fun onStop() {
        if (hasSensitiveWork() && !isLegacyCredentialTransitionActive()) hideAndFinish()
        super.onStop()
    }

    override fun onUserLeaveHint() {
        if (hasSensitiveWork() && !isLegacyCredentialTransitionActive()) hideAndFinish()
        super.onUserLeaveHint()
    }

    override fun onTrimMemory(level: Int) {
        @Suppress("DEPRECATION")
        if (
            level >= ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN &&
            hasSensitiveWork() &&
            !isLegacyCredentialTransitionActive()
        ) {
            hideAndFinish()
        }
        super.onTrimMemory(level)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        clearSensitiveState()
        super.onSaveInstanceState(outState)
        outState.clear()
    }

    override fun onProvideAssistData(outData: Bundle) {
        outData.clear()
    }

    override fun onProvideAssistContent(outContent: AssistContent) {
        outContent.webUri = null
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (
            isPlaintextVisible &&
            plaintextMarkedDisplayed &&
            event.actionMasked == MotionEvent.ACTION_DOWN
        ) {
            scheduleTimeout()
        }
        return super.dispatchTouchEvent(event)
    }

    override fun onDestroy() {
        clearSensitiveState()
        pendingLegacyCredentialResult.also { pendingLegacyCredentialResult = null }?.invoke(false)
        parserExecutor.shutdownNow()
        super.onDestroy()
    }

    override fun requestLegacyDeviceCredential(callback: (Boolean) -> Unit): Boolean {
        if (pendingLegacyCredentialResult != null || isFinishing || isDestroyed) return false
        val keyguard = getSystemService(KeyguardManager::class.java) ?: return false
        val credentialIntent = keyguard.createConfirmDeviceCredentialIntent(
            getString(R.string.secure_unlock_vault),
            getString(R.string.secure_unlock_vault_description),
        ) ?: return false
        pendingLegacyCredentialResult = callback
        return try {
            legacyCredentialLauncher.launch(credentialIntent)
            true
        } catch (_: RuntimeException) {
            pendingLegacyCredentialResult = null
            false
        }
    }

    private fun configureSecureWindow() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        window.decorView.apply {
            if (Build.VERSION.SDK_INT >= 26) {
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            }
            if (Build.VERSION.SDK_INT >= 30) {
                importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            }
            filterTouchesWhenObscured = true
        }
    }

    private fun buildContentView() {
        val horizontalPadding = dp(20)
        val topPadding = dp(18)
        val bottomPadding = dp(14)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(horizontalPadding, topPadding, horizontalPadding, bottomPadding)
            filterTouchesWhenObscured = true
            isSaveEnabled = false
            ViewCompat.setOnApplyWindowInsetsListener(this) { view, insets ->
                val safeDrawing = insets.getInsets(
                    WindowInsetsCompat.Type.systemBars() or
                        WindowInsetsCompat.Type.displayCutout(),
                )
                view.setPadding(
                    horizontalPadding + safeDrawing.left,
                    topPadding + safeDrawing.top,
                    horizontalPadding + safeDrawing.right,
                    bottomPadding + safeDrawing.bottom,
                )
                insets
            }
        }

        headingView = TextView(this).apply {
            text = getString(R.string.secure_viewer_title)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTypeface(typeface, Typeface.BOLD)
            isSaveEnabled = false
        }
        contactView = TextView(this).apply {
            visibility = View.GONE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setPadding(0, dp(6), 0, 0)
            isSaveEnabled = false
        }
        statusView = TextView(this).apply {
            text = getString(R.string.secure_decrypt_checking)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setPadding(0, dp(10), 0, dp(10))
            isSaveEnabled = false
        }
        progressView = ProgressBar(this).apply {
            isIndeterminate = true
            isSaveEnabled = false
        }
        plaintextView = SecurePlaintextView(this).apply {
            id = R.id.secure_viewer_plaintext
            visibility = View.GONE
            beforeSecureTextDraw = ::beforePlaintextDraw
            onSecureTextDrawn = ::onPlaintextDrawn
        }
        val messageScroller = ScrollView(this).apply {
            isFillViewport = true
            isSaveEnabled = false
            if (Build.VERSION.SDK_INT >= 26) {
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            }
            addView(
                plaintextView,
                ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }

        decryptButton = Button(this).apply {
            id = R.id.secure_decrypt_confirm_button
            text = getString(R.string.secure_decrypt_confirm)
            visibility = View.GONE
            isAllCaps = false
            isSaveEnabled = false
            setOnClickListener {
                val ciphertext = pendingConfirmationCiphertext ?: return@setOnClickListener
                pendingConfirmationCiphertext = null
                visibility = View.GONE
                beginParsing(ciphertext)
            }
        }
        replyButton = Button(this).apply {
            text = getString(R.string.secure_viewer_reply)
            visibility = View.GONE
            isAllCaps = false
            isSaveEnabled = false
            setOnClickListener { openSecureReply() }
        }
        val hideButton = Button(this).apply {
            text = getString(R.string.secure_viewer_hide_now)
            isAllCaps = false
            isSaveEnabled = false
            setOnClickListener { hideAndFinish() }
        }
        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
            isSaveEnabled = false
            addView(decryptButton, weightedButtonParams())
            addView(replyButton, weightedButtonParams())
            addView(hideButton, weightedButtonParams())
        }

        root.addView(headingView)
        root.addView(contactView)
        root.addView(statusView)
        root.addView(
            progressView,
            LinearLayout.LayoutParams(dp(40), dp(40)).apply { gravity = Gravity.CENTER_HORIZONTAL },
        )
        root.addView(
            messageScroller,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
        )
        root.addView(actions)
        setContentView(root)
    }

    private fun beginParsing(source: CharSequence) {
        when (val selection = CiphertextSelection.parse(source)) {
            is CiphertextSelection.Result.Invalid -> showFailure(R.string.secure_decrypt_invalid_selection)
            is CiphertextSelection.Result.Valid -> {
                val requestGeneration = ++generation
                statusView.text = getString(R.string.secure_decrypt_checking)
                parseFuture = parserExecutor.submit {
                    val parsed = SecureDecryptRuntime.parse(selection.parts)
                    mainHandler.post { onParsed(requestGeneration, parsed) }
                }
            }
        }
    }

    private fun onParsed(requestGeneration: Long, result: ParseResult) {
        parseFuture = null
        if (requestGeneration != generation || isFinishing || isDestroyed) {
            if (result is ParseResult.Success) runCatching { result.parsed.close() }
            return
        }
        when (result) {
            is ParseResult.Failure -> showFailure(result.reason.stringResource())
            is ParseResult.Success -> {
                parsedCiphertext = result.parsed
                statusView.text = getString(R.string.secure_decrypt_unlocking)
                decryptOperation = SecureDecryptRuntime.decrypt(this, result.parsed) { decryption ->
                    mainHandler.post { onDecrypted(requestGeneration, decryption) }
                }
            }
        }
    }

    private fun onDecrypted(requestGeneration: Long, result: DecryptResult) {
        decryptOperation = null
        pendingConfirmationCiphertext = null
        if (::decryptButton.isInitialized) decryptButton.visibility = View.GONE
        runCatching { parsedCiphertext?.close() }
        parsedCiphertext = null
        if (requestGeneration != generation || isFinishing || isDestroyed) {
            if (result is DecryptResult.Success) runCatching { result.message.close() }
            return
        }
        generation++
        when (result) {
            is DecryptResult.Failure -> showFailure(result.reason.stringResource())
            is DecryptResult.Success -> showMessage(result.message)
        }
    }

    private fun showMessage(message: DecryptedMessage) {
        if (!isForeground) {
            runCatching { message.close() }
            hideAndFinish()
            return
        }
        val wipeableText = WipeableText.decodeUtf8(message.plaintext)
        message.plaintext.close()
        if (wipeableText == null) {
            runCatching { message.close() }
            showFailure(R.string.secure_decrypt_invalid_ciphertext)
            return
        }

        decryptedMessage = message
        plaintextMarkedDisplayed = false
        plaintextView.setSecureText(wipeableText)
        plaintextView.visibility = View.VISIBLE
        progressView.visibility = View.GONE
        contactView.text = getString(R.string.secure_viewer_contact, message.localContactLabel)
        contactView.visibility = View.VISIBLE
        statusView.text = getString(
            when (message.contactStatus) {
                DecryptedContactStatus.VERIFIED -> R.string.secure_viewer_verified
                DecryptedContactStatus.UNVERIFIED -> R.string.secure_viewer_unverified
            },
        )
        replyButton.visibility = if (message.replyToken == null) View.GONE else View.VISIBLE
        isPlaintextVisible = true
        mainHandler.removeCallbacks(renderTimeoutAction)
        mainHandler.postDelayed(renderTimeoutAction, RENDER_TIMEOUT_MILLIS)
    }

    private fun beforePlaintextDraw(): Boolean {
        val allowed = isForeground &&
            isPlaintextVisible &&
            !isFinishing &&
            !isDestroyed &&
            SecureDecryptRuntime.canDisplayPlaintext()
        if (!allowed) mainHandler.post { hideAndFinish() }
        return allowed
    }

    private fun hasSensitiveWork(): Boolean =
        parseFuture != null ||
            parsedCiphertext != null ||
            decryptOperation != null ||
            decryptedMessage != null ||
            pendingConfirmationCiphertext != null ||
            isPlaintextVisible

    private fun isLegacyCredentialTransitionActive(): Boolean =
        pendingLegacyCredentialResult != null

    private fun onPlaintextDrawn() {
        val message = decryptedMessage ?: return
        if (!isPlaintextVisible || plaintextMarkedDisplayed) return
        if (runCatching { message.markDisplayed() }.isFailure) {
            mainHandler.post { hideAndFinish() }
            return
        }
        plaintextMarkedDisplayed = true
        mainHandler.removeCallbacks(renderTimeoutAction)
        scheduleTimeout()
    }

    private fun showFailure(messageResource: Int) {
        progressView.visibility = View.GONE
        plaintextView.visibility = View.GONE
        replyButton.visibility = View.GONE
        statusView.text = getString(messageResource)
    }

    private fun openSecureReply() {
        val message = decryptedMessage ?: return
        val token = message.replyToken ?: return
        val opened = SecureDecryptRuntime.openSecureReply(this, token)
        if (opened) {
            hideAndFinish()
        } else {
            statusView.text = getString(R.string.secure_reply_unavailable)
            scheduleTimeout()
        }
    }

    private fun scheduleTimeout() {
        mainHandler.removeCallbacks(timeoutAction)
        val timeout = SecureDecryptRuntime.viewerTimeoutMillis().coerceIn(
            MIN_VIEWER_TIMEOUT_MILLIS,
            MAX_VIEWER_TIMEOUT_MILLIS,
        )
        mainHandler.postDelayed(timeoutAction, timeout)
    }

    private fun hideAndFinish() {
        clearSensitiveState()
        setResult(RESULT_CANCELED)
        if (!isFinishing) finish()
    }

    private fun clearSensitiveState() {
        generation++
        mainHandler.removeCallbacks(timeoutAction)
        mainHandler.removeCallbacks(renderTimeoutAction)
        parseFuture?.cancel(true)
        parseFuture = null
        runCatching { decryptOperation?.cancel() }
        decryptOperation = null
        pendingConfirmationCiphertext = null
        if (::decryptButton.isInitialized) decryptButton.visibility = View.GONE
        runCatching { parsedCiphertext?.close() }
        parsedCiphertext = null
        if (::plaintextView.isInitialized) plaintextView.clearSecureText()
        runCatching { decryptedMessage?.close() }
        decryptedMessage = null
        isPlaintextVisible = false
        plaintextMarkedDisplayed = false
        if (::contactView.isInitialized) {
            contactView.text = null
            contactView.visibility = View.GONE
        }
    }

    private fun ParseFailureReason.stringResource(): Int = when (this) {
        ParseFailureReason.UNSUPPORTED_VERSION -> R.string.secure_decrypt_unsupported_version
        ParseFailureReason.MISSING_PART -> R.string.secure_decrypt_missing_part
        ParseFailureReason.TOO_MANY_PARTS -> R.string.secure_decrypt_too_many_parts
        ParseFailureReason.WRONG_CONTACT -> R.string.secure_decrypt_wrong_contact
        ParseFailureReason.INVALID_FORMAT,
        ParseFailureReason.INCONSISTENT_PARTS,
        -> R.string.secure_decrypt_invalid_selection
        ParseFailureReason.INTERNAL_ERROR -> R.string.secure_decrypt_unavailable
    }

    private fun DecryptFailureReason.stringResource(): Int = when (this) {
        DecryptFailureReason.VAULT_LOCKED -> R.string.secure_decrypt_vault_locked
        DecryptFailureReason.AUTHENTICATION_CANCELLED -> R.string.secure_decrypt_auth_cancelled
        DecryptFailureReason.WRONG_CONTACT -> R.string.secure_decrypt_wrong_contact
        DecryptFailureReason.REPLAY -> R.string.secure_decrypt_replay
        DecryptFailureReason.MISSING_PART -> R.string.secure_decrypt_missing_part
        DecryptFailureReason.KEY_CHANGED -> R.string.secure_decrypt_key_changed
        DecryptFailureReason.SESSION_ERROR -> R.string.secure_decrypt_session_error
        DecryptFailureReason.INVALID_CIPHERTEXT -> R.string.secure_decrypt_invalid_ciphertext
        DecryptFailureReason.INTERNAL_ERROR -> R.string.secure_decrypt_unavailable
    }

    private fun weightedButtonParams() = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
        marginStart = dp(4)
        marginEnd = dp(4)
    }

    private fun dp(value: Int): Int = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP,
        value.toFloat(),
        resources.displayMetrics,
    ).toInt()

    companion object {
        private const val EXTRA_CIPHERTEXT = "org.cipherboard.securekeyboard.extra.CIPHERTEXT"
        private const val MIN_VIEWER_TIMEOUT_MILLIS = 10_000L
        private const val MAX_VIEWER_TIMEOUT_MILLIS = 5 * 60_000L
        private const val RENDER_TIMEOUT_MILLIS = 3_000L

        fun createCiphertextIntent(context: Context, ciphertext: CharSequence): Intent =
            Intent(context, SecureMessageViewerActivity::class.java).apply {
                require(ciphertext.length <= CiphertextSelection.MAX_SELECTION_CHARS)
                action = "${context.packageName}.action.VIEW_CIPHERTEXT"
                putExtra(EXTRA_CIPHERTEXT, ciphertext.toString())
            }
    }
}
