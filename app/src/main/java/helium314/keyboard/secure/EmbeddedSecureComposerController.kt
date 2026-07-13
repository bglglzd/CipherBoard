// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.annotation.SuppressLint
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
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
import android.widget.Spinner
import android.widget.TextView
import androidx.core.view.ViewCompat
import helium314.keyboard.latin.InputAttributes
import helium314.keyboard.latin.LatinIME
import helium314.keyboard.latin.R
import helium314.keyboard.latin.common.ColorType
import helium314.keyboard.latin.settings.Settings
import helium314.keyboard.latin.utils.InputTypeUtils
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.TransportMode
import org.cipherboard.securekeyboard.runtime.PreparedOutbound
import org.cipherboard.securekeyboard.runtime.SecureContactSummary
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securekeyboard.runtime.SecureRuntimeError
import org.cipherboard.securekeyboard.runtime.SecureRuntimeException
import org.cipherboard.securestorage.ContactVerificationStatus

private const val AUTOFILL_NO_EXCLUDE_DESCENDANTS = 8

/** Owns the volatile draft, embedded panel and ciphertext-only delivery workflow for the IME. */
class EmbeddedSecureComposerController(
    private val ime: LatinIME,
) {
    private val runtime by lazy(LazyThreadSafetyMode.NONE) { SecureKeyboardRuntime.get() }
    private val stableInputTarget = View(ime)

    private var container: FrameLayout? = null
    private var panel: LinearLayout? = null
    private var draftView: SecureDraftView? = null
    private var contactSpinner: Spinner? = null
    private var contactStatus: TextView? = null
    private var countView: TextView? = null
    private var encryptButton: Button? = null
    private var contextButton: Button? = null
    private var transportGroup: RadioGroup? = null

    private var inputConnection: EmbeddedSecureInputConnection? = null
    private var contacts: List<SecureContactSummary> = emptyList()
    private var active = false
    private var passwordAcknowledged = true
    private var awaitingUnlock = false
    private var hostScope: EmbeddedHostScope? = null
    private var pendingCount = 0
    private var uncertainPendingCount = 0
    private var pendingStateKnown = false
    private var insertedRevision = Long.MIN_VALUE
    private var pendingDraftRevision: Long? = null
    private var ownerExists: Boolean? = null
    private var runtimeStateError: Int? = null
    private var pendingStateError: Int? = null

    fun attach(inputView: View) {
        val newContainer = inputView.findViewById<FrameLayout>(R.id.embedded_secure_composer_container)
        detachPanelViews()
        container = newContainer
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

    fun activate(editorInfo: EditorInfo?, uid: Int, connectionToken: IBinder?): Boolean {
        if (active) return acceptsHost(editorInfo, uid, connectionToken)
        val hostInfo = editorInfo ?: return false
        val scope = EmbeddedHostScope.from(hostInfo, uid, connectionToken) ?: return false
        if (container == null) return false
        hostScope = scope
        passwordAcknowledged = !isPasswordInput(hostInfo.inputType)
        awaitingUnlock = false
        insertedRevision = Long.MIN_VALUE
        pendingDraftRevision = null
        active = true
        runtime.onForegrounded()
        inputConnection = EmbeddedSecureInputConnection(
            stableInputTarget,
            acceptsInput = ::acceptsPlaintextInput,
            onChanged = ::onDraftChanged,
        )
        container?.visibility = View.VISIBLE
        panel?.visibility = View.VISIBLE
        refreshRuntimeState()
        return true
    }

    /** Called only after InputLogic has finished against the local connection. */
    fun deactivate() {
        if (!active && inputConnection == null) return
        awaitingUnlock = false
        active = false
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
        SecureImeBridge.clear()
        runtime.onBackgrounded()
    }

    fun acceptsHost(editorInfo: EditorInfo?, uid: Int, connectionToken: IBinder?): Boolean =
        hostScope?.matches(editorInfo, uid, connectionToken) == true

    fun markUnlockStarted() {
        if (!active) return
        // Authentication temporarily backgrounds the IME. A draft left behind after the vault
        // timed out must not survive that transition.
        if (!runtime.isVaultUnlocked && inputConnection?.isEmpty() == false) {
            ime.clearEmbeddedSecureDraft()
        }
        hostScope?.armUnlockRebind()
        awaitingUnlock = true
    }

    fun consumeUnlockReturn(editorInfo: EditorInfo?, uid: Int, connectionToken: IBinder?): Boolean {
        if (!active || !awaitingUnlock) return false
        val scope = hostScope ?: return false
        if (!scope.rebindAfterUnlock(editorInfo, uid, connectionToken)) return false
        awaitingUnlock = false
        runtime.onForegrounded()
        refreshRuntimeState()
        return true
    }

    fun isAwaitingUnlock(): Boolean = active && awaitingUnlock

    fun onScreenOff() {
        if (!active) return
        awaitingUnlock = false
        ime.forceCloseEmbeddedSecureComposer()
    }

    fun refreshAfterInputStarted() {
        if (!active) return
        runtime.onForegrounded()
        refreshRuntimeState()
    }

    fun currentDraftUtf8Length(): Int? = inputConnection?.utf8Length()

    fun acceptsPlaintextInput(): Boolean {
        if (!active || !passwordAcknowledged) return false
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
        contactSpinner?.onItemSelectedListener = null
        draftView?.onLocalCursorRequested = null
        encryptButton?.setOnClickListener(null)
        contextButton?.setOnClickListener(null)
        wipeDisplayedDraft()
        container?.removeAllViews()
        panel = null
        draftView = null
        contactSpinner = null
        contactStatus = null
        countView = null
        encryptButton = null
        contextButton = null
        transportGroup = null
    }

    fun clearDraftFromIme() {
        inputConnection?.wipe()
        insertedRevision = Long.MIN_VALUE
        pendingDraftRevision = null
        setStatus(defaultStatus())
        updateCountsAndActions()
    }

    private fun refreshRuntimeState() {
        if (!active) return
        runtime.lockIfExpired()
        val unlocked = runtime.isVaultUnlocked
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
        context.visibility = View.VISIBLE
        when {
            !passwordAcknowledged -> {
                setStatus(R.string.embedded_secure_password_warning)
                context.setText(R.string.embedded_secure_continue)
                context.setOnClickListener {
                    passwordAcknowledged = true
                    renderStatusAndContext()
                    updateCountsAndActions()
                }
            }
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
        val estimate = utf8Bytes?.let(::estimatedCiphertextCharacters) ?: 0
        countView?.text = ime.getString(R.string.embedded_secure_draft_count, characters, estimate)
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
                pendingStateKnown &&
                if (uncertainPendingCount > 0 || pendingCount > 0) {
                    true
                } else {
                    hasDraft && withinLimit && !alreadyInserted
                }
            alpha = if (isEnabled) 1f else DISABLED_CONTROL_ALPHA
        }
        if (hasDraft && !withinLimit) setStatus(R.string.embedded_secure_message_too_large)
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
            runtime.encrypt(contactId, plaintext, selectedTransportMode()).use { outbound ->
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

    private fun selectedTransportMode(): TransportMode =
        if (transportGroup?.checkedRadioButtonId == R.id.secure_transport_sms) {
            TransportMode.SMS_COMPACT
        } else {
            TransportMode.UNIVERSAL
        }

    private fun currentPlaintextLimitBytes(): Int =
        if (selectedTransportMode() == TransportMode.SMS_COMPACT) SMS_PLAINTEXT_LIMIT_BYTES
        else CipherBoardCrypto.MAX_PLAINTEXT_BYTES

    private fun estimatedCiphertextCharacters(plaintextBytes: Int): Int {
        if (plaintextBytes == 0) return 0
        val payload = plaintextBytes + OLM_OVERHEAD_ESTIMATE
        return (payload * 4 + 2) / 3 + UNIVERSAL_ENVELOPE_OVERHEAD_ESTIMATE
    }

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

    @SuppressLint("WrongConstant")
    private fun buildPanel(parent: FrameLayout) {
        val context = parent.context
        val configuration = context.resources.configuration
        val compact = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
        val wide = configuration.screenWidthDp >= WIDE_LAYOUT_MIN_WIDTH_DP
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
        header.addView(ImageView(context).apply {
            setImageResource(R.drawable.ic_secure_composer)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LinearLayout.LayoutParams(dp(28), dp(28)).apply { marginEnd = dp(6) })
        header.addView(TextView(context).apply {
            text = context.getString(R.string.embedded_secure_mode)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        header.addView(iconButton(
            context,
            R.id.embedded_secure_clear,
            R.drawable.sym_keyboard_clear_clipboard_rounded,
            R.string.embedded_secure_clear_description,
        ) { ime.clearEmbeddedSecureDraft() })
        header.addView(iconButton(
            context,
            R.id.embedded_secure_close,
            R.drawable.ic_close_rounded,
            R.string.embedded_secure_close_description,
        ) { ime.requestCloseEmbeddedSecureComposer() })
        root.addView(header, matchWidth())

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
        root.addView(contactSpinner, matchWidth().apply { topMargin = dp(2) })

        draftView = SecureDraftView(context).apply {
            id = R.id.embedded_secure_draft
            hint = context.getString(R.string.embedded_secure_draft_hint)
            minLines = if (compact) 1 else 2
            maxLines = if (compact) 2 else 3
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
        root.addView(draftView, matchWidth().apply {
            topMargin = dp(3)
            bottomMargin = dp(3)
        })

        contactStatus = TextView(context).apply {
            id = R.id.embedded_secure_status
            maxLines = if (compact) 3 else 4
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        root.addView(contactStatus, matchWidth())

        contextButton = Button(context).apply {
            id = R.id.embedded_secure_context_action
            minHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            minimumHeight = dp(MINIMUM_TOUCH_TARGET_DP)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(10), dp(3), dp(10), dp(3))
        }
        root.addView(contextButton, matchWidth().apply { topMargin = dp(2) })

        val actions = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        transportGroup = RadioGroup(context).apply {
            orientation = RadioGroup.HORIZONTAL
            val itemLayout = {
                if (wide) {
                    LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                    )
                } else {
                    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                }
            }
            addView(RadioButton(context).apply {
                id = R.id.secure_transport_universal
                text = context.getString(R.string.secure_transport_universal)
                isChecked = true
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                buttonTintList = ColorStateList.valueOf(Settings.getValues().mColors.get(ColorType.KEY_TEXT))
            }, itemLayout())
            addView(RadioButton(context).apply {
                id = R.id.secure_transport_sms
                text = context.getString(R.string.secure_transport_sms)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                buttonTintList = ColorStateList.valueOf(Settings.getValues().mColors.get(ColorType.KEY_TEXT))
            }, itemLayout())
            setOnCheckedChangeListener { _, _ -> updateCountsAndActions() }
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
        if (wide) {
            actions.addView(
                transportGroup,
                0,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
            root.addView(actions, matchWidth().apply { topMargin = dp(2) })
        } else {
            root.addView(transportGroup, matchWidth())
            root.addView(actions, matchWidth().apply { topMargin = dp(2) })
        }

        applyKeyboardColors(root)
        parent.addView(root, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
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
        encryptButton?.let { colors.setBackground(it, ColorType.KEY_BACKGROUND) }
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
        private const val OLM_OVERHEAD_ESTIMATE = 256
        private const val UNIVERSAL_ENVELOPE_OVERHEAD_ESTIMATE = 80
        private const val SMS_CHUNK_BYTES = 48
        private const val MAX_TRANSPORT_PARTS = 128
        private const val SMS_OLM_OVERHEAD_BUDGET = 512
        private const val SMS_PLAINTEXT_LIMIT_BYTES =
            SMS_CHUNK_BYTES * MAX_TRANSPORT_PARTS * 3 / 4 - SMS_OLM_OVERHEAD_BUDGET
    }
}

private data class PendingCounts(val ready: Int, val uncertain: Int) {
    companion object {
        val EMPTY = PendingCounts(0, 0)
    }
}

internal class EmbeddedHostScope private constructor(
    private val packageName: String,
    private val uid: Int,
    private val fieldId: Int,
    private val fieldName: String?,
    private val inputType: Int,
    private val imeOptions: Int,
    private var connectionToken: IBinder,
) {
    private var unlockRebindArmed = false

    fun matches(editorInfo: EditorInfo?, currentUid: Int, currentToken: IBinder?): Boolean =
        metadataMatches(editorInfo, currentUid) && currentToken != null && currentToken === connectionToken

    fun armUnlockRebind() {
        unlockRebindArmed = true
    }

    /** Consumes the one token replacement authorized by an explicit Vault unlock transition. */
    fun rebindAfterUnlock(editorInfo: EditorInfo?, currentUid: Int, newToken: IBinder?): Boolean {
        if (!unlockRebindArmed || !metadataMatches(editorInfo, currentUid) || newToken == null) {
            return false
        }
        connectionToken = newToken
        unlockRebindArmed = false
        return true
    }

    private fun metadataMatches(editorInfo: EditorInfo?, currentUid: Int): Boolean = editorInfo != null &&
        packageName == editorInfo.packageName && uid == currentUid && fieldId == editorInfo.fieldId &&
        fieldName == editorInfo.fieldName && inputType == editorInfo.inputType && imeOptions == editorInfo.imeOptions

    companion object {
        fun from(editorInfo: EditorInfo?, uid: Int, connectionToken: IBinder?): EmbeddedHostScope? {
            val info = editorInfo ?: return null
            val packageName = info.packageName?.takeIf { it.isNotBlank() } ?: return null
            if (uid < 0 || connectionToken == null) return null
            return EmbeddedHostScope(
                packageName,
                uid,
                info.fieldId,
                info.fieldName,
                info.inputType,
                info.imeOptions,
                connectionToken,
            )
        }
    }
}
