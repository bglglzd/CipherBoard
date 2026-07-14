// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.annotation.SuppressLint
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.text.TextUtils
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.core.view.ViewCompat
import helium314.keyboard.latin.InputAttributes
import helium314.keyboard.latin.LatinIME
import helium314.keyboard.latin.R
import helium314.keyboard.latin.common.ColorType
import helium314.keyboard.latin.settings.Settings
import helium314.keyboard.latin.utils.InputTypeUtils
import helium314.keyboard.secure.decrypt.CiphertextClipboardReader
import helium314.keyboard.secure.decrypt.CiphertextSelection
import helium314.keyboard.secure.decrypt.DecryptFailureReason
import helium314.keyboard.secure.decrypt.DecryptOperation
import helium314.keyboard.secure.decrypt.DecryptResult
import helium314.keyboard.secure.decrypt.DecryptedContactStatus
import helium314.keyboard.secure.decrypt.DecryptedMessage
import helium314.keyboard.secure.decrypt.ParseFailureReason
import helium314.keyboard.secure.decrypt.ParseResult
import helium314.keyboard.secure.decrypt.ParsedCiphertext
import helium314.keyboard.secure.decrypt.SecureDecryptRuntime
import helium314.keyboard.secure.decrypt.SecurePlaintextView
import helium314.keyboard.secure.decrypt.WipeableText
import org.cipherboard.cryptocore.TransportPresentation
import org.cipherboard.securekeyboard.runtime.MessagePresentationPreferences
import org.cipherboard.securekeyboard.runtime.PreparedOutbound
import org.cipherboard.securekeyboard.runtime.SecureContactSummary
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securekeyboard.runtime.SecureRuntimeError
import org.cipherboard.securekeyboard.runtime.SecureRuntimeException
import org.cipherboard.securestorage.ContactVerificationStatus
import java.util.concurrent.Executors
import java.util.concurrent.Future

private const val AUTOFILL_NO_EXCLUDE_DESCENDANTS = 8

/** Owns the volatile draft, embedded panel and ciphertext-only delivery workflow for the IME. */
class EmbeddedSecureComposerController(
    private val ime: LatinIME,
) {
    private val runtime by lazy(LazyThreadSafetyMode.NONE) { SecureKeyboardRuntime.get() }
    private val stableInputTarget = View(ime)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val parserExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "cipherboard-ime-parse").apply { isDaemon = true }
    }
    private val workerResultHandoffs = OwnedMainThreadResultHandoffs(
        postToMain = { callback -> mainHandler.post(callback) },
        removeFromMain = { callback -> mainHandler.removeCallbacks(callback) },
    )

    private var container: FrameLayout? = null
    private var panel: LinearLayout? = null
    private var standardStripContainer: View? = null
    private var keyboardViewWrapper: View? = null
    private var compactLayout = false
    private var modeGroup: RadioGroup? = null
    private var encryptSection: LinearLayout? = null
    private var decryptSection: LinearLayout? = null
    private var draftView: SecureDraftView? = null
    private var contactSpinner: Spinner? = null
    private var contactStatus: TextView? = null
    private var countView: TextView? = null
    private var encryptButton: Button? = null
    private var contextButton: Button? = null
    private var ciphertextSummary: TextView? = null
    private var decryptButton: Button? = null
    private var clearButton: ImageButton? = null
    private var plaintextScroller: ScrollView? = null
    private var plaintextView: SecurePlaintextView? = null

    private var inputConnection: EmbeddedSecureInputConnection? = null
    private var contacts: List<SecureContactSummary> = emptyList()
    private var active = false
    private var passwordAcknowledged = true
    private var awaitingUnlock = false
    private var unlockActivityCompleted = false
    private var unlockBridgeToken: String? = null
    private var hostScope: EmbeddedHostScope? = null
    private var pendingCount = 0
    private var uncertainPendingCount = 0
    private var pendingStateKnown = false
    private var insertedRevision = Long.MIN_VALUE
    private var pendingDraftRevision: Long? = null
    private var ownerExists: Boolean? = null
    private var runtimeStateError: Int? = null
    private var pendingStateError: Int? = null
    private var mode = EmbeddedMode.ENCRYPT
    private var decryptStage = EmbeddedDecryptStage.IDLE
    private var decryptStatusResource = R.string.embedded_secure_decrypt_clipboard_prompt
    private var decryptGeneration = 0L
    private var loadedCiphertextCharacters = 0
    private var loadedCiphertextParts = 0
    private var parseFuture: Future<*>? = null
    private var parseRequestGeneration: Long? = null
    private var parsedCiphertext: ParsedCiphertext? = null
    private var decryptOperation: DecryptOperation? = null
    private var decryptRequestToken: Any? = null
    private var decryptedMessage: DecryptedMessage? = null
    private var decryptedMessageMarkedDisplayed = false
    private val decryptTimeout = Runnable {
        if (active && mode == EmbeddedMode.DECRYPT) {
            hideDecryptedMessage(R.string.embedded_secure_message_hidden)
        }
    }
    private val decryptRenderTimeout = Runnable {
        if (
            active &&
            mode == EmbeddedMode.DECRYPT &&
            decryptStage == EmbeddedDecryptStage.DISPLAYED &&
            !decryptedMessageMarkedDisplayed
        ) {
            hideDecryptedMessage(R.string.secure_decrypt_unavailable)
        }
    }
    private val unlockReturnTimeout = Runnable {
        if (active && awaitingUnlock) {
            unlockBridgeToken?.let(EmbeddedVaultUnlockBridge::cancel)
            unlockBridgeToken = null
            awaitingUnlock = false
            ime.forceCloseEmbeddedSecureComposer()
        }
    }

    fun attach(inputView: View) {
        val newContainer = inputView.findViewById<FrameLayout>(R.id.embedded_secure_composer_container)
        detachPanelViews()
        container = newContainer
        standardStripContainer = inputView.findViewById(R.id.standard_strip_container)
        keyboardViewWrapper = inputView.findViewById(R.id.keyboard_view_wrapper)
        buildPanel(newContainer)
        newContainer.visibility = if (active) View.VISIBLE else View.GONE
        if (active) {
            syncDraftView()
            refreshRuntimeState()
        }
    }

    fun isActive(): Boolean = active

    fun localInputConnection(): InputConnection? = if (active) inputConnection else null

    fun effectiveEditorInfo(): EditorInfo? = if (active) secureEditorInfo() else null

    fun activate(
        editorInfo: EditorInfo?,
        uid: Int,
        connectionToken: IBinder?,
        connectionIdentity: Any?,
    ): Boolean {
        if (active) return acceptsHost(editorInfo, uid, connectionToken, connectionIdentity)
        val hostInfo = editorInfo ?: return false
        val scope = EmbeddedHostScope.from(hostInfo, uid, connectionToken, connectionIdentity) ?: return false
        if (container == null) return false
        hostScope = scope
        passwordAcknowledged = !isPasswordInput(hostInfo.inputType)
        awaitingUnlock = false
        unlockActivityCompleted = false
        mode = EmbeddedMode.ENCRYPT
        clearEmbeddedDecryptState(resetLoaded = true)
        insertedRevision = Long.MIN_VALUE
        pendingDraftRevision = null
        active = true
        workerResultHandoffs.open()
        runtime.onSecureImeForegrounded()
        inputConnection = EmbeddedSecureInputConnection(
            stableInputTarget,
            acceptsInput = ::acceptsPlaintextInput,
            onChanged = ::onDraftChanged,
        )
        container?.visibility = View.VISIBLE
        panel?.visibility = View.VISIBLE
        applyModeVisibility()
        refreshRuntimeState()
        return true
    }

    /** Called only after InputLogic has finished against the local connection. */
    fun deactivate() {
        workerResultHandoffs.close()
        if (!active && inputConnection == null) return
        awaitingUnlock = false
        unlockActivityCompleted = false
        mainHandler.removeCallbacks(unlockReturnTimeout)
        unlockBridgeToken?.let(EmbeddedVaultUnlockBridge::cancel)
        unlockBridgeToken = null
        active = false
        clearEmbeddedDecryptState(resetLoaded = true)
        inputConnection?.wipe()
        inputConnection = null
        wipeDisplayedDraft()
        contacts = emptyList()
        hostScope = null
        pendingCount = 0
        uncertainPendingCount = 0
        pendingStateKnown = false
        insertedRevision = Long.MIN_VALUE
        pendingDraftRevision = null
        ownerExists = null
        runtimeStateError = null
        pendingStateError = null
        container?.visibility = View.GONE
        panel?.visibility = View.GONE
        restoreStandardKeyboardSurfaces()
        SecureImeBridge.clear()
        runtime.onSecureImeBackgrounded()
    }

    fun destroy() {
        deactivate()
        detachPanelViews()
        mainHandler.removeCallbacksAndMessages(null)
        parserExecutor.shutdownNow()
    }

    fun acceptsHost(
        editorInfo: EditorInfo?,
        uid: Int,
        connectionToken: IBinder?,
        connectionIdentity: Any?,
    ): Boolean = hostScope?.matches(editorInfo, uid, connectionToken, connectionIdentity) == true

    fun markUnlockStarted(): String? {
        if (!active) return null
        // Authentication temporarily backgrounds the IME. A draft left behind after the vault
        // timed out must not survive that transition.
        if (!runtime.isVaultUnlocked && inputConnection?.isEmpty() == false) {
            ime.clearEmbeddedSecureDraft()
        }
        hostScope?.armUnlockRebind()
        awaitingUnlock = true
        unlockActivityCompleted = false
        unlockBridgeToken?.let(EmbeddedVaultUnlockBridge::cancel)
        val token = EmbeddedVaultUnlockBridge.begin(::onVaultUnlockActivityFinished)
        unlockBridgeToken = token
        mainHandler.removeCallbacks(unlockReturnTimeout)
        mainHandler.postDelayed(unlockReturnTimeout, UNLOCK_ACTIVITY_TIMEOUT_MILLIS)
        return token
    }

    private fun onVaultUnlockActivityFinished(unlocked: Boolean) {
        unlockBridgeToken = null
        mainHandler.removeCallbacks(unlockReturnTimeout)
        if (!active || !awaitingUnlock) return
        if (!unlocked) {
            awaitingUnlock = false
            unlockActivityCompleted = false
            ime.forceCloseEmbeddedSecureComposer()
            return
        }
        unlockActivityCompleted = true
        runtime.onSecureImeForegrounded()
        mainHandler.postDelayed(unlockReturnTimeout, UNLOCK_HOST_RETURN_TIMEOUT_MILLIS)
    }

    fun cancelUnlockLaunch(token: String) {
        if (unlockBridgeToken != token) return
        EmbeddedVaultUnlockBridge.cancel(token)
        unlockBridgeToken = null
        awaitingUnlock = false
        unlockActivityCompleted = false
        mainHandler.removeCallbacks(unlockReturnTimeout)
        ime.forceCloseEmbeddedSecureComposer()
    }

    fun consumeUnlockReturn(
        editorInfo: EditorInfo?,
        uid: Int,
        connectionToken: IBinder?,
        connectionIdentity: Any?,
    ): Boolean {
        if (!active || !awaitingUnlock || !unlockActivityCompleted) return false
        val scope = hostScope ?: return false
        if (!scope.rebindAfterUnlock(editorInfo, uid, connectionToken, connectionIdentity)) return false
        awaitingUnlock = false
        unlockActivityCompleted = false
        mainHandler.removeCallbacks(unlockReturnTimeout)
        runtime.onSecureImeForegrounded()
        refreshRuntimeState()
        maybeStartPendingDecrypt()
        return true
    }

    fun isAwaitingUnlock(): Boolean = active && awaitingUnlock

    fun onScreenOff() {
        if (!active) return
        awaitingUnlock = false
        unlockActivityCompleted = false
        mainHandler.removeCallbacks(unlockReturnTimeout)
        unlockBridgeToken?.let(EmbeddedVaultUnlockBridge::cancel)
        unlockBridgeToken = null
        ime.forceCloseEmbeddedSecureComposer()
    }

    fun refreshAfterInputStarted() {
        if (!active) return
        runtime.onSecureImeForegrounded()
        refreshRuntimeState()
        maybeStartPendingDecrypt()
    }

    fun currentDraftUtf8Length(): Int? = inputConnection?.utf8Length()

    fun acceptsPlaintextInput(): Boolean {
        if (!active || mode != EmbeddedMode.ENCRYPT || !passwordAcknowledged) return false
        runtime.lockIfExpired()
        return runtime.isVaultUnlocked
    }

    private fun onDraftChanged(connection: EmbeddedSecureInputConnection) {
        if (!active || connection !== inputConnection) return
        syncDraftView()
        updateCountsAndActions()
    }

    private fun syncDraftView() {
        val target = draftView?.displayBuffer ?: return
        inputConnection?.copyInto(target) ?: EmbeddedSecureInputConnection.wipeEditable(target, clearSpans = false)
        inputConnection?.let { draftView?.setLocalCursor(it.selectionEnd()) }
            ?: draftView?.hideLocalCursor()
    }

    private fun wipeDisplayedDraft() {
        draftView?.displayBuffer?.let { EmbeddedSecureInputConnection.wipeEditable(it, clearSpans = false) }
        draftView?.hideLocalCursor()
    }

    private fun detachPanelViews() {
        clearEmbeddedDecryptState(resetLoaded = true)
        restoreStandardKeyboardSurfaces()
        contactSpinner?.onItemSelectedListener = null
        draftView?.onLocalCursorRequested = null
        encryptButton?.setOnClickListener(null)
        decryptButton?.setOnClickListener(null)
        clearButton?.setOnClickListener(null)
        modeGroup?.setOnCheckedChangeListener(null)
        contextButton?.setOnClickListener(null)
        wipeDisplayedDraft()
        container?.removeAllViews()
        panel = null
        standardStripContainer = null
        keyboardViewWrapper = null
        modeGroup = null
        encryptSection = null
        decryptSection = null
        draftView = null
        contactSpinner = null
        contactStatus = null
        countView = null
        encryptButton = null
        contextButton = null
        ciphertextSummary = null
        decryptButton = null
        clearButton = null
        plaintextScroller = null
        plaintextView?.beforeSecureTextDraw = null
        plaintextView?.onSecureTextDrawn = null
        plaintextView = null
    }

    fun clearDraftFromIme() {
        inputConnection?.wipe()
        insertedRevision = Long.MIN_VALUE
        pendingDraftRevision = null
        if (mode == EmbeddedMode.ENCRYPT) setStatus(defaultStatus())
        updateCountsAndActions()
    }

    private fun setMode(next: EmbeddedMode) {
        if (mode == next) return
        if (next == EmbeddedMode.DECRYPT) {
            ime.prepareEmbeddedDraftForEncryption()
            draftView?.hideLocalCursor()
        } else {
            clearEmbeddedDecryptState(resetLoaded = true)
        }
        mode = next
        applyModeVisibility()
        renderStatusAndContext()
        updateCountsAndActions()
    }

    private fun clearCurrentMode() {
        if (mode == EmbeddedMode.ENCRYPT) {
            ime.clearEmbeddedSecureDraft()
        } else {
            clearEmbeddedDecryptState(resetLoaded = true)
            renderStatusAndContext()
        }
    }

    private fun applyModeVisibility() {
        val encrypting = mode == EmbeddedMode.ENCRYPT
        updateSectionVisibility()
        modeGroup?.check(
            if (encrypting) R.id.embedded_secure_encrypt_mode else R.id.embedded_secure_decrypt_mode,
        )
        clearButton?.let { button ->
            button.contentDescription = ime.getString(
                if (encrypting) {
                    R.string.embedded_secure_clear_description
                } else {
                    R.string.embedded_secure_clear_decrypt_description
                },
            )
            ViewCompat.setTooltipText(button, button.contentDescription)
        }
        if (encrypting) syncDraftView() else draftView?.hideLocalCursor()
        updateStandardKeyboardSurfaces()
        updateDecryptUi()
    }

    private fun updateStandardKeyboardSurfaces() {
        if (!active) {
            restoreStandardKeyboardSurfaces()
            return
        }
        standardStripContainer?.visibility = View.GONE
        val canTypePrivateDraft = mode == EmbeddedMode.ENCRYPT && canComposePrivateDraft()
        keyboardViewWrapper?.visibility =
            if (canTypePrivateDraft) View.VISIBLE else View.GONE
    }

    private fun updateSectionVisibility() {
        val encrypting = mode == EmbeddedMode.ENCRYPT
        val showEncryptControls = encrypting &&
            (!active || !compactLayout || canComposePrivateDraft())
        encryptSection?.visibility = if (showEncryptControls) View.VISIBLE else View.GONE
        decryptSection?.visibility = if (encrypting) View.GONE else View.VISIBLE
    }

    private fun canComposePrivateDraft(): Boolean =
            passwordAcknowledged &&
            runtime.isVaultUnlocked &&
            ownerExists == true &&
            contacts.isNotEmpty()

    private fun restoreStandardKeyboardSurfaces() {
        standardStripContainer?.visibility = View.VISIBLE
        keyboardViewWrapper?.visibility = View.VISIBLE
    }

    private fun onDecryptAction() {
        if (!active || mode != EmbeddedMode.DECRYPT) return
        when (decryptStage) {
            EmbeddedDecryptStage.DISPLAYED -> {
                hideDecryptedMessage(R.string.embedded_secure_message_hidden)
                return
            }
            EmbeddedDecryptStage.CHECKING,
            EmbeddedDecryptStage.DECRYPTING,
            -> return
            else -> Unit
        }
        if (parsedCiphertext != null) {
            if (runtime.isVaultUnlocked) {
                maybeStartPendingDecrypt()
            } else {
                decryptStage = EmbeddedDecryptStage.WAITING_FOR_UNLOCK
                decryptStatusResource = R.string.secure_decrypt_unlocking
                updateDecryptUi()
                renderStatusAndContext()
                ime.launchEmbeddedVaultUnlock()
            }
            return
        }
        readClipboardAndParse()
    }

    private fun readClipboardAndParse() {
        clearEmbeddedDecryptState(resetLoaded = true)
        val source = CiphertextClipboardReader.read(ime)
        if (source == null) {
            showDecryptFailure(R.string.secure_clipboard_decrypt_invalid)
            return
        }
        val selection = CiphertextSelection.parse(source)
        if (selection !is CiphertextSelection.Result.Valid) {
            showDecryptFailure(R.string.secure_clipboard_decrypt_invalid)
            return
        }
        loadedCiphertextCharacters = source.length
        loadedCiphertextParts = selection.parts.size
        decryptStage = EmbeddedDecryptStage.CHECKING
        decryptStatusResource = R.string.secure_decrypt_checking
        val requestGeneration = ++decryptGeneration
        updateDecryptUi()
        renderStatusAndContext()
        parseRequestGeneration = requestGeneration
        val resultHandoffToken = workerResultHandoffs.capture()
        parseFuture = parserExecutor.submit {
            val result = SecureDecryptRuntime.parse(selection.parts)
            workerResultHandoffs.post(
                token = resultHandoffToken,
                value = result,
                deliver = { delivered -> onParsedCiphertext(requestGeneration, delivered) },
                abandon = ::closeParseResult,
            )
        }
    }

    private fun onParsedCiphertext(requestGeneration: Long, result: ParseResult) {
        if (parseRequestGeneration == requestGeneration) {
            parseFuture = null
            parseRequestGeneration = null
        }
        if (requestGeneration != decryptGeneration || !active || mode != EmbeddedMode.DECRYPT) {
            if (result is ParseResult.Success) runCatching { result.parsed.close() }
            return
        }
        when (result) {
            is ParseResult.Failure -> showDecryptFailure(result.reason.decryptStringResource())
            is ParseResult.Success -> {
                parsedCiphertext = result.parsed
                decryptStage = EmbeddedDecryptStage.WAITING_FOR_UNLOCK
                if (runtime.isVaultUnlocked) {
                    maybeStartPendingDecrypt()
                } else {
                    decryptStatusResource = R.string.secure_decrypt_unlocking
                    updateDecryptUi()
                    renderStatusAndContext()
                    ime.launchEmbeddedVaultUnlock()
                }
            }
        }
    }

    private fun maybeStartPendingDecrypt() {
        if (!active || mode != EmbeddedMode.DECRYPT || decryptOperation != null) return
        val parsed = parsedCiphertext ?: return
        runtime.lockIfExpired()
        if (!runtime.isVaultUnlocked) {
            decryptStage = EmbeddedDecryptStage.WAITING_FOR_UNLOCK
            decryptStatusResource = if (awaitingUnlock) {
                R.string.secure_decrypt_unlocking
            } else {
                R.string.secure_decrypt_vault_locked
            }
            updateDecryptUi()
            renderStatusAndContext()
            return
        }
        if (ownerExists == false || runtimeStateError != null) {
            renderStatusAndContext()
            updateDecryptUi()
            return
        }
        decryptStage = EmbeddedDecryptStage.DECRYPTING
        decryptStatusResource = R.string.embedded_secure_decrypting
        val requestGeneration = decryptGeneration
        val requestToken = Any()
        decryptRequestToken = requestToken
        val resultHandoffToken = workerResultHandoffs.capture()
        updateDecryptUi()
        renderStatusAndContext()
        decryptOperation = SecureDecryptRuntime.decryptUnlocked(parsed) { result ->
            workerResultHandoffs.post(
                token = resultHandoffToken,
                value = result,
                deliver = { delivered ->
                    onDecryptedMessage(requestToken, requestGeneration, parsed, delivered)
                },
                abandon = { abandoned -> closeDecryptResult(parsed, abandoned) },
            )
        }
    }

    private fun onDecryptedMessage(
        requestToken: Any,
        requestGeneration: Long,
        requestParsed: ParsedCiphertext,
        result: DecryptResult,
    ) {
        if (
            requestToken !== decryptRequestToken ||
            requestGeneration != decryptGeneration ||
            !active ||
            mode != EmbeddedMode.DECRYPT
        ) {
            closeDecryptResult(requestParsed, result)
            return
        }
        decryptOperation = null
        decryptRequestToken = null
        if (parsedCiphertext === requestParsed) {
            parsedCiphertext = null
        }
        runCatching { requestParsed.close() }
        when (result) {
            is DecryptResult.Failure -> showDecryptFailure(result.reason.decryptStringResource())
            is DecryptResult.Success -> {
                runtime.lockIfExpired()
                if (!runtime.isVaultUnlocked) {
                    result.message.close()
                    showDecryptFailure(R.string.secure_decrypt_vault_locked)
                } else {
                    showDecryptedMessage(result.message)
                }
            }
        }
    }

    private fun showDecryptedMessage(message: DecryptedMessage) {
        val view = plaintextView
        val text = try {
            WipeableText.decodeUtf8(message.plaintext)
        } catch (_: RuntimeException) {
            null
        } finally {
            message.plaintext.close()
        }
        if (view == null || text == null) {
            text?.close()
            message.close()
            showDecryptFailure(R.string.secure_decrypt_invalid_ciphertext)
            return
        }
        try {
            plaintextScroller?.scrollTo(0, 0)
            view.setSecureText(text)
        } catch (_: RuntimeException) {
            view.clearSecureText()
            message.close()
            showDecryptFailure(R.string.secure_decrypt_unavailable)
            return
        }
        decryptedMessage = message
        decryptedMessageMarkedDisplayed = false
        decryptStage = EmbeddedDecryptStage.DISPLAYED
        decryptStatusResource = R.string.secure_viewer_verified
        updateDecryptUi()
        renderStatusAndContext()
        mainHandler.removeCallbacks(decryptTimeout)
        mainHandler.removeCallbacks(decryptRenderTimeout)
        mainHandler.postDelayed(decryptRenderTimeout, DECRYPT_RENDER_TIMEOUT_MILLIS)
    }

    private fun beforeDecryptedPlaintextDraw(): Boolean {
        if (
            !active ||
            mode != EmbeddedMode.DECRYPT ||
            decryptStage != EmbeddedDecryptStage.DISPLAYED ||
            decryptedMessage == null
        ) {
            return false
        }
        runtime.lockIfExpired()
        if (runtime.isVaultUnlocked) return true
        mainHandler.post {
            if (active && mode == EmbeddedMode.DECRYPT && decryptedMessage != null) {
                hideDecryptedMessage(R.string.secure_decrypt_vault_locked)
            }
        }
        return false
    }

    private fun onDecryptedPlaintextDrawn() {
        val message = decryptedMessage ?: return
        if (
            !active ||
            mode != EmbeddedMode.DECRYPT ||
            decryptStage != EmbeddedDecryptStage.DISPLAYED ||
            decryptedMessageMarkedDisplayed
        ) {
            return
        }
        runtime.lockIfExpired()
        if (!runtime.isVaultUnlocked) {
            mainHandler.post {
                if (decryptedMessage === message) {
                    hideDecryptedMessage(R.string.secure_decrypt_vault_locked)
                }
            }
            return
        }
        if (runCatching { message.markDisplayed() }.isFailure) {
            mainHandler.post {
                if (decryptedMessage === message) {
                    hideDecryptedMessage(R.string.secure_decrypt_unavailable)
                }
            }
            return
        }
        decryptedMessageMarkedDisplayed = true
        mainHandler.removeCallbacks(decryptRenderTimeout)
        mainHandler.postDelayed(
            decryptTimeout,
            SecureDecryptRuntime.viewerTimeoutMillis().coerceIn(
                MIN_VIEWER_TIMEOUT_MILLIS,
                MAX_VIEWER_TIMEOUT_MILLIS,
            ),
        )
    }

    private fun showDecryptFailure(resource: Int) {
        decryptStage = EmbeddedDecryptStage.FAILED
        decryptStatusResource = resource
        updateDecryptUi()
        renderStatusAndContext()
    }

    private fun hideDecryptedMessage(statusResource: Int) {
        clearEmbeddedDecryptState(resetLoaded = true, statusResource = statusResource)
        renderStatusAndContext()
    }

    private fun clearEmbeddedDecryptState(
        resetLoaded: Boolean,
        statusResource: Int = R.string.embedded_secure_decrypt_clipboard_prompt,
    ) {
        decryptGeneration++
        workerResultHandoffs.drain()
        mainHandler.removeCallbacks(decryptTimeout)
        mainHandler.removeCallbacks(decryptRenderTimeout)
        parseFuture?.cancel(true)
        parseFuture = null
        parseRequestGeneration = null
        decryptRequestToken = null
        decryptOperation?.cancel()
        decryptOperation = null
        runCatching { parsedCiphertext?.close() }
        parsedCiphertext = null
        plaintextView?.clearSecureText()
        plaintextScroller?.scrollTo(0, 0)
        runCatching { decryptedMessage?.close() }
        decryptedMessage = null
        decryptedMessageMarkedDisplayed = false
        decryptStage = EmbeddedDecryptStage.IDLE
        decryptStatusResource = statusResource
        if (resetLoaded) {
            loadedCiphertextCharacters = 0
            loadedCiphertextParts = 0
        }
        updateDecryptUi()
    }

    private fun closeParseResult(result: ParseResult) {
        if (result is ParseResult.Success) runCatching { result.parsed.close() }
    }

    private fun closeDecryptResult(parsed: ParsedCiphertext, result: DecryptResult) {
        runCatching { parsed.close() }
        if (result is DecryptResult.Success) runCatching { result.message.close() }
    }

    private fun updateDecryptUi() {
        ciphertextSummary?.text = if (loadedCiphertextCharacters > 0) {
            ime.getString(
                R.string.embedded_secure_decrypt_loaded,
                loadedCiphertextCharacters,
                loadedCiphertextParts,
            )
        } else {
            ime.getString(R.string.embedded_secure_decrypt_clipboard_prompt)
        }
        plaintextScroller?.visibility =
            if (decryptStage == EmbeddedDecryptStage.DISPLAYED) View.VISIBLE else View.INVISIBLE
        decryptButton?.apply {
            text = ime.getString(
                when (decryptStage) {
                    EmbeddedDecryptStage.CHECKING -> R.string.secure_decrypt_checking
                    EmbeddedDecryptStage.WAITING_FOR_UNLOCK ->
                        if (runtime.isVaultUnlocked) {
                            R.string.secure_decrypt_confirm
                        } else {
                            R.string.embedded_secure_unlock_and_decrypt
                        }
                    EmbeddedDecryptStage.DECRYPTING -> R.string.embedded_secure_decrypting
                    EmbeddedDecryptStage.DISPLAYED -> R.string.embedded_secure_hide_message
                    EmbeddedDecryptStage.IDLE,
                    EmbeddedDecryptStage.FAILED,
                    -> R.string.embedded_secure_paste_and_decrypt
                },
            )
            contentDescription = ime.getString(
                if (decryptStage == EmbeddedDecryptStage.DISPLAYED) {
                    R.string.embedded_secure_hide_message
                } else {
                    R.string.embedded_secure_decrypt_action_description
                },
            )
            isEnabled = active && mode == EmbeddedMode.DECRYPT && passwordAcknowledged &&
                ownerExists != false && runtimeStateError == null &&
                decryptStage != EmbeddedDecryptStage.CHECKING &&
                decryptStage != EmbeddedDecryptStage.DECRYPTING
            alpha = if (isEnabled) 1f else DISABLED_CONTROL_ALPHA
        }
    }

    private fun refreshRuntimeState() {
        if (!active) return
        runtime.lockIfExpired()
        val unlocked = runtime.isVaultUnlocked
        if (!unlocked && (decryptOperation != null || decryptedMessage != null)) {
            clearEmbeddedDecryptState(
                resetLoaded = true,
                statusResource = R.string.secure_decrypt_vault_locked,
            )
        }
        val previousId = selectedContact()?.internalId()
        ownerExists = null
        runtimeStateError = null
        contacts = if (unlocked) {
            runCatching {
                ownerExists = runtime.owner() != null
                if (ownerExists == true) runtime.listContacts() else emptyList()
            }.getOrElse {
                runtimeStateError = errorStatusResource(it)
                emptyList()
            }
        } else {
            emptyList()
        }
        updateContactSpinner(previousId)
        previousId?.fill(0)
        refreshPendingState()
        renderStatusAndContext()
        updateCountsAndActions()
        updateDecryptUi()
        updateSectionVisibility()
        updateStandardKeyboardSurfaces()
    }

    private fun updateContactSpinner(previousId: ByteArray?) {
        val spinner = contactSpinner ?: return
        val names = when {
            !runtime.isVaultUnlocked -> listOf(ime.getString(R.string.secure_vault_locked))
            contacts.isEmpty() -> listOf(ime.getString(R.string.secure_no_contacts))
            else -> contacts.map { it.localName }
        }
        val colors = Settings.getValues().mColors
        spinner.adapter = ContactSpinnerAdapter(
            spinner.context,
            names,
            colors.get(ColorType.KEY_TEXT),
            colors.get(ColorType.MAIN_BACKGROUND),
        )
        spinner.setPopupBackgroundDrawable(ColorDrawable(colors.get(ColorType.MAIN_BACKGROUND)))
        ViewCompat.setBackgroundTintList(
            spinner,
            ColorStateList.valueOf(colors.get(ColorType.KEY_TEXT)),
        )
        if (previousId != null && contacts.isNotEmpty()) {
            val previousIndex = contacts.indexOfFirst { candidate ->
                val id = candidate.internalId()
                try {
                    id.contentEquals(previousId)
                } finally {
                    id.fill(0)
                }
            }
            if (previousIndex >= 0) spinner.setSelection(previousIndex)
        }
        spinner.isEnabled = contacts.isNotEmpty()
        spinner.alpha = if (spinner.isEnabled) 1f else DISABLED_LABEL_ALPHA
        updateContactAccessibilityDescription()
    }

    private fun updateContactAccessibilityDescription() {
        val spinner = contactSpinner ?: return
        val selectedLabel = spinner.selectedItem?.toString()?.takeIf { it.isNotBlank() }
        val recipient = ime.getString(R.string.secure_recipient)
        spinner.contentDescription = if (selectedLabel == null) recipient else "$recipient: $selectedLabel"
    }

    private fun selectedContact(): SecureContactSummary? =
        contacts.getOrNull(contactSpinner?.selectedItemPosition ?: -1)

    private fun selectedContactReady(): Boolean {
        val contact = selectedContact() ?: return false
        return !contact.requiresRepairing && !contact.sessionError && !contact.keyChanged &&
            contact.verificationStatus != ContactVerificationStatus.PAIRING_REQUIRED
    }

    private fun refreshPendingState() {
        val selected = selectedContact()
        if (!runtime.isVaultUnlocked || selected == null) {
            pendingCount = 0
            uncertainPendingCount = 0
            pendingStateKnown = false
            pendingStateError = null
            return
        }
        val contactId = selected.internalId()
        val result = try {
            runCatching {
                runtime.pendingOutbound().let { pending ->
                    try {
                        var ready = 0
                        var uncertain = 0
                        pending.forEach { outbound ->
                            if (outbound.matchesContact(contactId)) {
                                if (outbound.canAutomaticallyRetry) ready++ else uncertain++
                            }
                        }
                        PendingCounts(ready, uncertain)
                    } finally {
                        pending.forEach(PreparedOutbound::close)
                    }
                }
            }
        } finally {
            contactId.fill(0)
        }
        pendingStateKnown = result.isSuccess
        pendingStateError = result.exceptionOrNull()?.let(::errorStatusResource)
        val counts = result.getOrDefault(PendingCounts.EMPTY)
        pendingCount = counts.ready
        uncertainPendingCount = counts.uncertain
    }

    private fun renderStatusAndContext() {
        val context = contextButton ?: return
        contactStatus?.visibility = View.VISIBLE
        context.visibility = View.VISIBLE
        when {
            !passwordAcknowledged -> {
                setStatus(R.string.embedded_secure_password_warning)
                context.setText(R.string.embedded_secure_continue)
                context.setOnClickListener {
                    passwordAcknowledged = true
                    renderStatusAndContext()
                    updateCountsAndActions()
                    updateDecryptUi()
                    updateStandardKeyboardSurfaces()
                }
            }
            mode == EmbeddedMode.DECRYPT -> renderDecryptStatusAndContext(context)
            !runtime.isVaultUnlocked -> {
                setStatus(R.string.embedded_secure_unlock_to_encrypt)
                context.setText(R.string.secure_unlock_vault)
                context.setOnClickListener { ime.launchEmbeddedVaultUnlock() }
            }
            runtimeStateError != null || pendingStateError != null -> {
                setStatus(runtimeStateError ?: pendingStateError ?: R.string.secure_operation_failed)
                context.setText(R.string.embedded_secure_open_cipherboard)
                context.setOnClickListener { ime.openCipherBoardHomeFromEmbeddedComposer() }
            }
            ownerExists == false -> {
                setStatus(R.string.embedded_secure_no_identity)
                context.setText(R.string.embedded_secure_open_cipherboard)
                context.setOnClickListener { ime.openCipherBoardHomeFromEmbeddedComposer() }
            }
            contacts.isEmpty() -> {
                setStatus(R.string.secure_pair_contact_first)
                context.setText(R.string.embedded_secure_add_contact)
                context.setOnClickListener { ime.openCipherBoardHomeFromEmbeddedComposer() }
            }
            else -> {
                context.visibility = View.GONE
                setStatus(defaultStatus())
            }
        }
    }

    private fun renderDecryptStatusAndContext(context: Button) {
        when {
            !runtime.isVaultUnlocked -> {
                context.visibility = View.INVISIBLE
                if (decryptStage == EmbeddedDecryptStage.IDLE) {
                    contactStatus?.visibility = View.INVISIBLE
                } else {
                    setStatus(decryptStatusResource)
                }
            }
            runtimeStateError != null -> {
                setStatus(runtimeStateError ?: R.string.secure_operation_failed)
                context.setText(R.string.embedded_secure_open_cipherboard)
                context.setOnClickListener { ime.openCipherBoardHomeFromEmbeddedComposer() }
            }
            ownerExists == false -> {
                setStatus(R.string.embedded_secure_no_identity)
                context.setText(R.string.embedded_secure_open_cipherboard)
                context.setOnClickListener { ime.openCipherBoardHomeFromEmbeddedComposer() }
            }
            else -> {
                val message = decryptedMessage
                if (decryptStage == EmbeddedDecryptStage.DISPLAYED && message != null) {
                    setStatus(
                        ime.getString(
                            when (message.contactStatus) {
                                DecryptedContactStatus.VERIFIED ->
                                    R.string.embedded_secure_decrypted_verified
                                DecryptedContactStatus.UNVERIFIED ->
                                    R.string.embedded_secure_decrypted_unverified
                            },
                            message.localContactLabel,
                        ),
                    )
                    if (message.replyToken == null) {
                        context.visibility = View.INVISIBLE
                    } else {
                        context.visibility = View.VISIBLE
                        context.setText(R.string.secure_viewer_reply)
                        context.setOnClickListener { replyToDecryptedContact() }
                    }
                } else if (decryptStage == EmbeddedDecryptStage.IDLE) {
                    context.visibility = View.INVISIBLE
                    contactStatus?.visibility = View.INVISIBLE
                } else {
                    context.visibility = View.INVISIBLE
                    setStatus(decryptStatusResource)
                }
            }
        }
    }

    private fun replyToDecryptedContact() {
        val token = decryptedMessage?.replyToken ?: return
        val index = contacts.indexOfFirst { contact ->
            val candidate = contact.internalId()
            try {
                token.matchesContact(candidate)
            } finally {
                candidate.fill(0)
            }
        }
        if (index < 0) {
            setStatus(R.string.secure_reply_unavailable)
            return
        }
        performSecureReplyTransition(
            clearPrivateDraft = ime::clearEmbeddedSecureDraft,
            enterEncryptMode = { setMode(EmbeddedMode.ENCRYPT) },
            selectReplyContact = { contactSpinner?.setSelection(index) },
        )
        renderStatusAndContext()
        updateCountsAndActions()
    }

    private fun defaultStatus(): CharSequence = when {
        selectedContact() == null -> ime.getString(R.string.embedded_secure_contact_unavailable)
        selectedContact()?.keyChanged == true ||
            selectedContact()?.verificationStatus == ContactVerificationStatus.KEY_CHANGED ->
            ime.getString(R.string.secure_contact_key_changed)
        selectedContact()?.sessionError == true ||
            selectedContact()?.verificationStatus == ContactVerificationStatus.SESSION_ERROR ->
            ime.getString(R.string.secure_contact_session_error)
        selectedContact()?.requiresRepairing == true ||
            selectedContact()?.verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED ->
            ime.getString(R.string.secure_contact_pairing_required)
        uncertainPendingCount > 0 -> ime.getString(R.string.embedded_secure_delivery_uncertain)
        pendingCount > 0 -> ime.getString(R.string.embedded_secure_pending_blocks_new)
        selectedContact()?.verificationStatus == ContactVerificationStatus.VERIFIED ->
            ime.getString(R.string.secure_contact_verified)
        else -> ime.getString(R.string.secure_contact_unverified)
    }

    private fun updateCountsAndActions() {
        val connection = inputConnection
        val utf8Bytes = connection?.utf8Length()
        val characters = connection?.codePointCount() ?: 0
        countView?.text = ime.messagePresentationEstimateText(
            characters = characters,
            plaintextBytes = utf8Bytes ?: 0,
            presentation = currentMessagePresentation(),
        )
        val withinLimit = utf8Bytes != null && utf8Bytes <= currentPlaintextLimitBytes()
        val hasDraft = connection?.isEmpty() == false
        val alreadyInserted = connection != null && connection.revision == insertedRevision
        encryptButton?.apply {
            val actionText = ime.getString(
                when {
                    uncertainPendingCount > 0 -> R.string.embedded_secure_acknowledge_uncertain
                    pendingCount > 0 -> R.string.embedded_secure_retry_pending
                    else -> R.string.embedded_secure_encrypt
                },
            )
            text = actionText
            contentDescription = when {
                uncertainPendingCount > 0 ->
                    ime.getString(R.string.embedded_secure_acknowledge_uncertain_description)
                pendingCount > 0 -> actionText
                else -> ime.getString(R.string.embedded_secure_encrypt_description)
            }
            isEnabled = active && passwordAcknowledged && runtime.isVaultUnlocked && selectedContactReady() &&
                mode == EmbeddedMode.ENCRYPT &&
                pendingStateKnown &&
                if (uncertainPendingCount > 0 || pendingCount > 0) {
                    true
                } else {
                    hasDraft && withinLimit && !alreadyInserted
                }
            alpha = if (isEnabled) 1f else DISABLED_CONTROL_ALPHA
        }
        if (mode == EmbeddedMode.ENCRYPT && hasDraft && !withinLimit) {
            setStatus(R.string.embedded_secure_message_too_large)
        }
    }

    private fun encryptOrRetry() {
        if (!runtime.isVaultUnlocked) return renderStatusAndContext()
        if (uncertainPendingCount > 0) {
            acknowledgeUncertainDelivery()
            return
        }
        if (pendingCount > 0) {
            retryPendingCiphertext()
            return
        }
        if (!selectedContactReady()) return
        ime.prepareEmbeddedDraftForEncryption()
        val connection = inputConnection ?: return
        val utf8Bytes = connection.utf8Length() ?: return setStatus(R.string.secure_invalid_unicode)
        if (utf8Bytes == 0) return
        if (utf8Bytes > currentPlaintextLimitBytes()) {
            setStatus(R.string.embedded_secure_message_too_large)
            return
        }
        val plaintext = try {
            connection.copyUtf8()
        } catch (_: IllegalArgumentException) {
            return setStatus(R.string.secure_invalid_unicode)
        }
        val contactId = selectedContact()?.internalId() ?: run {
            plaintext.fill(0)
            return
        }
        pendingDraftRevision = connection.revision
        try {
            runtime.encrypt(
                contactId,
                plaintext,
                presentation = currentMessagePresentation(),
            ).use { outbound ->
                handleDeliveryResult(ime.deliverEmbeddedSecureOutbound(outbound), connection.revision)
            }
        } catch (error: Throwable) {
            plaintext.fill(0)
            setStatusForError(error)
        } finally {
            contactId.fill(0)
            refreshPendingState()
            updateCountsAndActions()
        }
    }

    private fun retryPendingCiphertext() {
        val contact = selectedContact() ?: return
        val contactId = contact.internalId()
        val selected = try {
            runtime.pendingOutbound().let { candidates ->
                val match = candidates.firstOrNull {
                    it.canAutomaticallyRetry && it.matchesContact(contactId)
                }
                candidates.filter { it !== match }.forEach(PreparedOutbound::close)
                match
            }
        } catch (error: Throwable) {
            setStatusForError(error)
            null
        } finally {
            contactId.fill(0)
        } ?: return
        try {
            handleDeliveryResult(
                ime.deliverEmbeddedSecureOutbound(selected),
                pendingDraftRevision ?: Long.MIN_VALUE,
            )
        } finally {
            selected.close()
            refreshPendingState()
            updateCountsAndActions()
        }
    }

    private fun acknowledgeUncertainDelivery() {
        val contactId = selectedContact()?.internalId() ?: return
        val selected = try {
            runtime.pendingOutbound().let { candidates ->
                val match = candidates.firstOrNull {
                    !it.canAutomaticallyRetry && it.matchesContact(contactId)
                }
                candidates.filter { it !== match }.forEach(PreparedOutbound::close)
                match
            }
        } catch (error: Throwable) {
            setStatusForError(error)
            null
        } finally {
            contactId.fill(0)
        } ?: return
        try {
            val operationId = selected.operationId()
            val completed = try {
                runtime.completeOutbound(operationId)
            } finally {
                operationId.fill(0)
            }
            setStatus(
                if (completed) R.string.embedded_secure_uncertain_cleared
                else R.string.secure_operation_failed,
            )
        } catch (error: Throwable) {
            setStatusForError(error)
        } finally {
            selected.close()
            refreshPendingState()
            updateCountsAndActions()
        }
    }

    private fun handleDeliveryResult(result: CiphertextDeliveryResult, revision: Long) {
        when (result) {
            CiphertextDeliveryResult.COMMITTED_AND_COMPLETED -> {
                insertedRevision = revision
                pendingDraftRevision = null
                setStatus(R.string.embedded_secure_ciphertext_inserted)
            }
            CiphertextDeliveryResult.HOST_COMMIT_UNCERTAIN -> {
                insertedRevision = revision
                pendingDraftRevision = null
                setStatus(R.string.embedded_secure_delivery_uncertain)
            }
            CiphertextDeliveryResult.COMMITTED_PENDING_CLEANUP -> {
                insertedRevision = revision
                pendingDraftRevision = null
                setStatus(R.string.embedded_secure_delivery_uncertain)
            }
            CiphertextDeliveryResult.NO_HANDOFF -> setStatus(R.string.embedded_secure_unavailable)
        }
    }

    private fun PreparedOutbound.matchesContact(contactId: ByteArray): Boolean {
        val candidate = contactId()
        return try {
            candidate.contentEquals(contactId)
        } finally {
            candidate.fill(0)
        }
    }

    private fun currentMessagePresentation(): TransportPresentation =
        MessagePresentationPreferences.read(ime)

    private fun currentPlaintextLimitBytes(): Int =
        maximumPlaintextBytes(currentMessagePresentation())

    private fun setStatus(resource: Int) = setStatus(ime.getString(resource))

    private fun setStatus(value: CharSequence) {
        contactStatus?.text = value
    }

    private fun setStatusForError(error: Throwable) {
        setStatus(errorStatusResource(error))
    }

    private fun errorStatusResource(error: Throwable): Int =
        when ((error as? SecureRuntimeException)?.reason) {
            SecureRuntimeError.CONTACT_NOT_READY -> R.string.secure_contact_not_ready
            SecureRuntimeError.CORRUPT_STATE -> R.string.secure_vault_corrupt
            else -> R.string.secure_operation_failed
        }

    private fun ParseFailureReason.decryptStringResource(): Int = when (this) {
        ParseFailureReason.UNSUPPORTED_VERSION -> R.string.secure_decrypt_unsupported_version
        ParseFailureReason.MISSING_PART -> R.string.secure_decrypt_missing_part
        ParseFailureReason.TOO_MANY_PARTS -> R.string.secure_decrypt_too_many_parts
        ParseFailureReason.WRONG_CONTACT -> R.string.secure_decrypt_wrong_contact
        ParseFailureReason.INVALID_FORMAT,
        ParseFailureReason.INCONSISTENT_PARTS,
        -> R.string.secure_decrypt_invalid_selection
        ParseFailureReason.INTERNAL_ERROR -> R.string.secure_decrypt_unavailable
    }

    private fun DecryptFailureReason.decryptStringResource(): Int = when (this) {
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

    @SuppressLint("WrongConstant")
    private fun buildPanel(parent: FrameLayout) {
        val context = parent.context
        val configuration = context.resources.configuration
        val compact = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
        compactLayout = compact
        val wide = configuration.screenWidthDp >= WIDE_LAYOUT_MIN_WIDTH_DP
        val constrainedHeight = configuration.screenHeightDp < CONSTRAINED_HEIGHT_DP ||
            configuration.fontScale >= LARGE_FONT_SCALE
        val root = LinearLayout(context).apply {
            id = R.id.embedded_secure_composer_panel
            orientation = LinearLayout.VERTICAL
            setPadding(dp(8), dp(if (compact) 4 else 6), dp(8), dp(if (compact) 4 else 6))
            ViewCompat.setImportantForAutofill(this, AUTOFILL_NO_EXCLUDE_DESCENDANTS)
            ViewCompat.setAccessibilityPaneTitle(this, context.getString(R.string.embedded_secure_mode))
        }
        panel = root

        val header = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val modeControl = RadioGroup(context).apply {
            id = R.id.embedded_secure_mode_group
            orientation = RadioGroup.HORIZONTAL
            addView(modeButton(
                context,
                R.id.embedded_secure_encrypt_mode,
                R.string.embedded_secure_encrypt_mode,
            ), weightedModeButtonParams())
            addView(modeButton(
                context,
                R.id.embedded_secure_decrypt_mode,
                R.string.embedded_secure_decrypt_mode,
            ), weightedModeButtonParams())
            check(
                if (mode == EmbeddedMode.ENCRYPT) {
                    R.id.embedded_secure_encrypt_mode
                } else {
                    R.id.embedded_secure_decrypt_mode
                },
            )
        }
        modeGroup = modeControl
        if (compact) {
            header.addView(
                modeControl,
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
            )
        } else {
            header.addView(ImageView(context).apply {
                setImageResource(R.drawable.ic_secure_composer)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }, LinearLayout.LayoutParams(dp(28), dp(28)).apply { marginEnd = dp(6) })
            header.addView(TextView(context).apply {
                text = context.getString(R.string.embedded_secure_mode)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
        val clear = iconButton(
            context,
            R.id.embedded_secure_clear,
            R.drawable.sym_keyboard_clear_clipboard_rounded,
            R.string.embedded_secure_clear_description,
        ) { clearCurrentMode() }
        clearButton = clear
        header.addView(clear)
        header.addView(iconButton(
            context,
            R.id.embedded_secure_close,
            R.drawable.ic_close_rounded,
            R.string.embedded_secure_close_description,
        ) { ime.requestCloseEmbeddedSecureComposer() })
        root.addView(header, matchWidth())
        if (!compact) {
            root.addView(modeControl, matchWidth().apply { topMargin = dp(2) })
        }

        val encryptRoot = LinearLayout(context).apply {
            id = R.id.embedded_secure_encrypt_section
            orientation = LinearLayout.VERTICAL
        }
        encryptSection = encryptRoot

        contactSpinner = Spinner(context).apply {
            id = R.id.embedded_secure_contact
            prompt = context.getString(R.string.secure_recipient)
            contentDescription = context.getString(R.string.secure_recipient)
            minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                    updateContactAccessibilityDescription()
                    refreshPendingState()
                    renderStatusAndContext()
                    updateCountsAndActions()
                }

                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {
                    updateContactAccessibilityDescription()
                    refreshPendingState()
                    updateCountsAndActions()
                }
            }
        }
        draftView = SecureDraftView(context).apply {
            id = R.id.embedded_secure_draft
            hint = context.getString(R.string.embedded_secure_draft_hint)
            minLines = if (compact) 1 else 2
            maxLines = if (compact) 1 else 3
            gravity = Gravity.TOP or Gravity.START
            isFocusable = false
            isFocusableInTouchMode = false
            isLongClickable = false
            setTextIsSelectable(false)
            isSaveEnabled = false
            onLocalCursorRequested = { offset ->
                inputConnection?.setSelection(offset, offset)
            }
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
            contentDescription = context.getString(R.string.embedded_secure_draft_private_description)
            ViewCompat.setImportantForAutofill(this, AUTOFILL_NO_EXCLUDE_DESCENDANTS)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            }
            if (Build.VERSION.SDK_INT >= 34) {
                setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
            }
        }
        if (compact) {
            val editorRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(
                    contactSpinner,
                    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.36f).apply {
                        marginEnd = dp(6)
                    },
                )
                addView(
                    draftView,
                    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.64f),
                )
            }
            encryptRoot.addView(editorRow, matchWidth().apply {
                topMargin = dp(2)
                bottomMargin = dp(2)
            })
        } else {
            encryptRoot.addView(contactSpinner, matchWidth().apply { topMargin = dp(2) })
            encryptRoot.addView(draftView, matchWidth().apply {
                topMargin = dp(3)
                bottomMargin = dp(3)
            })
        }

        val actions = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        countView = TextView(context).apply {
            id = R.id.embedded_secure_count
            gravity = Gravity.END
            maxLines = 2
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        }
        actions.addView(countView, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginStart = dp(4)
            marginEnd = dp(4)
        })
        encryptButton = Button(context).apply {
            id = R.id.embedded_secure_encrypt
            text = context.getString(R.string.embedded_secure_encrypt)
            contentDescription = context.getString(R.string.embedded_secure_encrypt_description)
            minHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(10), dp(4), dp(10), dp(4))
            setOnClickListener { encryptOrRetry() }
        }
        actions.addView(encryptButton, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        encryptRoot.addView(actions, matchWidth().apply { topMargin = dp(2) })
        root.addView(encryptRoot, matchWidth())

        val decryptRoot = LinearLayout(context).apply {
            id = R.id.embedded_secure_decrypt_section
            orientation = LinearLayout.VERTICAL
        }
        decryptSection = decryptRoot
        ciphertextSummary = TextView(context).apply {
            id = R.id.embedded_secure_ciphertext_summary
            maxLines = if (compact || constrainedHeight) 1 else 3
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            text = context.getString(R.string.embedded_secure_decrypt_clipboard_prompt)
        }
        decryptRoot.addView(ciphertextSummary, matchWidth().apply {
            topMargin = dp(4)
            bottomMargin = dp(3)
        })
        decryptButton = Button(context).apply {
            id = R.id.embedded_secure_decrypt_action
            minHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(10), dp(4), dp(10), dp(4))
            setOnClickListener { onDecryptAction() }
        }
        decryptRoot.addView(decryptButton, matchWidth())
        plaintextView = SecurePlaintextView(context).apply {
            id = R.id.embedded_secure_plaintext
            beforeSecureTextDraw = ::beforeDecryptedPlaintextDraw
            onSecureTextDrawn = ::onDecryptedPlaintextDrawn
        }
        plaintextScroller = ScrollView(context).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
            visibility = View.INVISIBLE
            addView(
                plaintextView,
                ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
        decryptRoot.addView(plaintextScroller, matchWidth().apply {
            height = dp(
                when {
                    compact -> DECRYPT_VIEW_HEIGHT_LANDSCAPE_DP
                    constrainedHeight -> DECRYPT_VIEW_HEIGHT_CONSTRAINED_DP
                    else -> DECRYPT_VIEW_HEIGHT_PORTRAIT_DP
                },
            )
            topMargin = dp(3)
        })
        root.addView(decryptRoot, matchWidth())

        contactStatus = TextView(context).apply {
            id = R.id.embedded_secure_status
            maxLines = if (compact) 1 else 4
            minHeight = dp(20)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        root.addView(contactStatus, matchWidth().apply { topMargin = dp(2) })

        contextButton = Button(context).apply {
            id = R.id.embedded_secure_context_action
            minHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(10), dp(3), dp(10), dp(3))
        }
        root.addView(contextButton, matchWidth().apply { topMargin = dp(2) })

        modeGroup?.setOnCheckedChangeListener { _, checkedId ->
            setMode(
                if (checkedId == R.id.embedded_secure_decrypt_mode) {
                    EmbeddedMode.DECRYPT
                } else {
                    EmbeddedMode.ENCRYPT
                },
            )
        }

        protectEmbeddedSecureInteractions(root)
        applyKeyboardColors(root)
        parent.addView(root, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        applyModeVisibility()
    }

    private fun iconButton(
        context: android.content.Context,
        id: Int,
        drawable: Int,
        description: Int,
        action: () -> Unit,
    ): ImageButton = ImageButton(context).apply {
        this.id = id
        setImageResource(drawable)
        contentDescription = context.getString(description)
        ViewCompat.setTooltipText(this, contentDescription)
        setPadding(dp(7), dp(7), dp(7), dp(7))
        setOnClickListener { action() }
        background = null
        minimumWidth = dp(MINIMUM_TOUCH_TARGET_DP)
        minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
    }

    private fun modeButton(
        context: android.content.Context,
        id: Int,
        label: Int,
    ): RadioButton = RadioButton(context).apply {
        this.id = id
        text = context.getString(label)
        gravity = Gravity.CENTER
        minHeight = dp(MINIMUM_TOUCH_TARGET_DP)
        minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        buttonTintList = ColorStateList.valueOf(Settings.getValues().mColors.get(ColorType.KEY_TEXT))
    }

    private fun weightedModeButtonParams() = LinearLayout.LayoutParams(
        0,
        ViewGroup.LayoutParams.WRAP_CONTENT,
        1f,
    )

    private fun applyKeyboardColors(root: ViewGroup) {
        val colors = Settings.getValues().mColors
        colors.setBackground(root, ColorType.STRIP_BACKGROUND)
        forEachView(root) { view ->
            when (view) {
                is TextView -> view.setTextColor(colors.get(ColorType.KEY_TEXT))
                is ImageView -> colors.setColor(view, ColorType.TOOL_BAR_KEY)
            }
        }
        val background = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(6).toFloat()
            setColor(colors.get(ColorType.MAIN_BACKGROUND))
            val keyText = colors.get(ColorType.KEY_TEXT)
            val stroke = Color.argb(
                110,
                Color.red(keyText),
                Color.green(keyText),
                Color.blue(keyText),
            )
            setStroke(dp(1), stroke)
        }
        draftView?.background = background
        draftView?.setHintTextColor(colors.get(ColorType.KEY_HINT_TEXT))
        plaintextView?.setSecureTextColor(colors.get(ColorType.KEY_TEXT))
        encryptButton?.let { colors.setBackground(it, ColorType.KEY_BACKGROUND) }
        decryptButton?.let { colors.setBackground(it, ColorType.KEY_BACKGROUND) }
        contextButton?.let { colors.setBackground(it, ColorType.KEY_BACKGROUND) }
    }

    private inner class ContactSpinnerAdapter(
        context: android.content.Context,
        values: List<String>,
        private val textColor: Int,
        private val dropDownBackgroundColor: Int,
    ) : ArrayAdapter<String>(context, 0, values) {
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View =
            bind(position, convertView, dropDown = false)

        override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View =
            bind(position, convertView, dropDown = true)

        private fun bind(position: Int, convertView: View?, dropDown: Boolean): TextView {
            return (convertView as? TextView ?: TextView(context)).apply {
                text = getItem(position).orEmpty()
                setTextColor(textColor)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
                gravity = Gravity.CENTER_VERTICAL or Gravity.START
                isSingleLine = true
                ellipsize = TextUtils.TruncateAt.END
                minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
                setPadding(dp(10), dp(4), dp(if (dropDown) 10 else 36), dp(4))
                setBackgroundColor(if (dropDown) dropDownBackgroundColor else Color.TRANSPARENT)
                isSaveEnabled = false
                filterTouchesWhenObscured = true
            }
        }
    }

    private fun forEachView(root: ViewGroup, block: (View) -> Unit) {
        for (index in 0 until root.childCount) {
            val child = root.getChildAt(index)
            block(child)
            if (child is ViewGroup) forEachView(child, block)
        }
    }

    private fun secureEditorInfo(): EditorInfo = EditorInfo().apply {
        packageName = ime.packageName
        fieldId = R.id.embedded_secure_draft
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI or
            EditorInfo.IME_FLAG_NO_FULLSCREEN
        privateImeOptions = InputAttributes.CIPHERBOARD_SECURE_EDITOR_OPTION
        initialSelStart = inputConnection?.selectionStart() ?: 0
        initialSelEnd = inputConnection?.selectionEnd() ?: initialSelStart
    }

    private fun isPasswordInput(inputType: Int): Boolean =
        InputTypeUtils.isPasswordInputType(inputType) || InputTypeUtils.isVisiblePasswordInputType(inputType)

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    private fun dp(value: Int): Int = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP,
        value.toFloat(),
        ime.resources.displayMetrics,
    ).toInt()

    companion object {
        private const val DISABLED_CONTROL_ALPHA = 0.55f
        private const val DISABLED_LABEL_ALPHA = 0.72f
        private const val MINIMUM_TOUCH_TARGET_DP = 44
        private const val WIDE_LAYOUT_MIN_WIDTH_DP = 600
        private const val CONSTRAINED_HEIGHT_DP = 560
        private const val LARGE_FONT_SCALE = 1.5f
        private const val DECRYPT_VIEW_HEIGHT_PORTRAIT_DP = 132
        private const val DECRYPT_VIEW_HEIGHT_CONSTRAINED_DP = 88
        private const val DECRYPT_VIEW_HEIGHT_LANDSCAPE_DP = 84
        private const val MIN_VIEWER_TIMEOUT_MILLIS = 10_000L
        private const val MAX_VIEWER_TIMEOUT_MILLIS = 5 * 60_000L
        private const val DECRYPT_RENDER_TIMEOUT_MILLIS = 3_000L
        private const val UNLOCK_ACTIVITY_TIMEOUT_MILLIS = 2 * 60_000L
        private const val UNLOCK_HOST_RETURN_TIMEOUT_MILLIS = 5_000L
    }
}

private enum class EmbeddedMode {
    ENCRYPT,
    DECRYPT,
}

internal inline fun performSecureReplyTransition(
    clearPrivateDraft: () -> Unit,
    enterEncryptMode: () -> Unit,
    selectReplyContact: () -> Unit,
) {
    clearPrivateDraft()
    enterEncryptMode()
    selectReplyContact()
}

internal fun protectEmbeddedSecureInteractions(view: View) {
    view.filterTouchesWhenObscured = true
    if (view is ViewGroup) {
        for (index in 0 until view.childCount) {
            protectEmbeddedSecureInteractions(view.getChildAt(index))
        }
    }
}

private enum class EmbeddedDecryptStage {
    IDLE,
    CHECKING,
    WAITING_FOR_UNLOCK,
    DECRYPTING,
    DISPLAYED,
    FAILED,
}

private data class PendingCounts(val ready: Int, val uncertain: Int) {
    companion object {
        val EMPTY = PendingCounts(0, 0)
    }
}

/**
 * Transfers ownership of worker results to the main thread without leaving closeable values in
 * callbacks that lifecycle teardown can remove. The queue starts closed and must be reopened for
 * each active controller lifetime.
 */
internal class OwnedMainThreadResultHandoffs(
    private val postToMain: (Runnable) -> Boolean,
    private val removeFromMain: (Runnable) -> Unit,
) {
    private val lock = Any()
    private val pending = mutableSetOf<OwnedDelivery<*>>()
    private var accepting = false
    private var generation = 0L

    fun open() {
        synchronized(lock) {
            generation++
            accepting = true
        }
    }

    fun capture(): Long? = synchronized(lock) { if (accepting) generation else null }

    fun close() {
        val abandoned = synchronized(lock) {
            generation++
            accepting = false
            pending.toList().also { pending.clear() }
        }
        abandon(abandoned)
    }

    fun drain() {
        val abandoned = synchronized(lock) {
            generation++
            pending.toList().also { pending.clear() }
        }
        abandon(abandoned)
    }

    fun <T : Any> post(
        token: Long?,
        value: T,
        deliver: (T) -> Unit,
        abandon: (T) -> Unit,
    ) {
        val delivery = OwnedDelivery(value, deliver, abandon, ::onDeliveryClaimed)
        val accepted = synchronized(lock) {
            if (accepting && token == generation) pending.add(delivery) else false
        }
        if (!accepted) {
            delivery.abandon()
            return
        }
        if (!postToMain(delivery)) {
            synchronized(lock) { pending.remove(delivery) }
            delivery.abandon()
        }
    }

    private fun onDeliveryClaimed(delivery: OwnedDelivery<*>) {
        synchronized(lock) { pending.remove(delivery) }
    }

    private fun abandon(deliveries: List<OwnedDelivery<*>>) {
        deliveries.forEach { delivery ->
            runCatching { removeFromMain(delivery) }
            runCatching { delivery.abandon() }
        }
    }

    private class OwnedDelivery<T : Any>(
        value: T,
        deliver: (T) -> Unit,
        abandon: (T) -> Unit,
        private val onClaimed: (OwnedDelivery<*>) -> Unit,
    ) : Runnable {
        private val lock = Any()
        private var value: T? = value
        private var deliver: ((T) -> Unit)? = deliver
        private var abandon: ((T) -> Unit)? = abandon

        override fun run() {
            val claimedValue: T
            val delivery: (T) -> Unit
            synchronized(lock) {
                claimedValue = value ?: return
                delivery = deliver ?: return
                value = null
                deliver = null
                abandon = null
            }
            onClaimed(this)
            delivery(claimedValue)
        }

        fun abandon() {
            val claimedValue: T
            val cleanup: (T) -> Unit
            synchronized(lock) {
                claimedValue = value ?: return
                cleanup = abandon ?: return
                value = null
                deliver = null
                abandon = null
            }
            cleanup(claimedValue)
        }
    }
}

internal class EmbeddedHostScope private constructor(
    private val packageName: String,
    private val uid: Int,
    private val fieldId: Int,
    private val fieldName: String?,
    private val inputType: Int,
    private val imeOptions: Int,
    private var connectionToken: IBinder?,
    private var connectionIdentity: Any,
) {
    private var unlockRebindArmed = false

    fun matches(
        editorInfo: EditorInfo?,
        currentUid: Int,
        currentToken: IBinder?,
        currentConnectionIdentity: Any?,
    ): Boolean = metadataMatches(editorInfo, currentUid) &&
        currentConnectionIdentity != null && currentConnectionIdentity === connectionIdentity &&
        (connectionToken == null || currentToken == null || currentToken === connectionToken)

    fun armUnlockRebind() {
        unlockRebindArmed = true
    }

    /** Consumes the one token replacement authorized by an explicit Vault unlock transition. */
    fun rebindAfterUnlock(
        editorInfo: EditorInfo?,
        currentUid: Int,
        newToken: IBinder?,
        newConnectionIdentity: Any?,
    ): Boolean {
        if (!unlockRebindArmed || !metadataMatches(editorInfo, currentUid) || newConnectionIdentity == null) {
            return false
        }
        connectionToken = newToken
        connectionIdentity = newConnectionIdentity
        unlockRebindArmed = false
        return true
    }

    private fun metadataMatches(editorInfo: EditorInfo?, currentUid: Int): Boolean = editorInfo != null &&
        packageName == editorInfo.packageName && uid == currentUid && fieldId == editorInfo.fieldId &&
        fieldName == editorInfo.fieldName && inputType == editorInfo.inputType && imeOptions == editorInfo.imeOptions

    companion object {
        fun from(
            editorInfo: EditorInfo?,
            uid: Int,
            connectionToken: IBinder?,
            connectionIdentity: Any?,
        ): EmbeddedHostScope? {
            val info = editorInfo ?: return null
            val packageName = info.packageName?.takeIf { it.isNotBlank() } ?: return null
            if (uid < 0 || connectionIdentity == null) return null
            return EmbeddedHostScope(
                packageName,
                uid,
                info.fieldId,
                info.fieldName,
                info.inputType,
                info.imeOptions,
                connectionToken,
                connectionIdentity,
            )
        }
    }
}
