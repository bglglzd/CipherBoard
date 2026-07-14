// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.annotation.SuppressLint
import android.app.Activity
import android.app.assist.AssistContent
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.database.ContentObserver
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.Spanned
import android.text.TextWatcher
import android.util.TypedValue
import android.view.ActionMode
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.ViewStructure
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.inputmethod.EditorInfoCompat
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.InputAttributes
import helium314.keyboard.latin.R
import org.cipherboard.cryptocore.TransportPresentation
import org.cipherboard.securekeyboard.runtime.MessagePresentationPreferences
import org.cipherboard.securekeyboard.runtime.PreparedOutbound
import org.cipherboard.securekeyboard.runtime.SecureContactSummary
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securekeyboard.runtime.SecureRuntimeError
import org.cipherboard.securekeyboard.runtime.SecureRuntimeException
import org.cipherboard.securekeyboard.runtime.VaultUnlockAction
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.KeystoreSecurityLevel
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import kotlin.math.ceil

// Stable android.view.View autofill importance values, passed through the API-safe compat setter.
private const val AUTOFILL_NO = 2
private const val AUTOFILL_NO_EXCLUDE_DESCENDANTS = 8

internal fun secureHandoffAllowed(
    imeTrusted: Boolean,
    passwordAcknowledged: Boolean,
    hasLiveHandoffToken: Boolean,
    vaultUnlocked: Boolean,
    contactReady: Boolean,
): Boolean = imeTrusted && passwordAcknowledged && hasLiveHandoffToken && vaultUnlocked && contactReady

/** Plaintext editor isolated from the host app's InputConnection. */
@SuppressLint("WrongConstant")
class SecureComposerActivity : FragmentActivity() {
    private lateinit var runtime: SecureKeyboardRuntime
    private lateinit var vaultStatus: TextView
    private lateinit var imeWarning: TextView
    private lateinit var ownerSection: LinearLayout
    private lateinit var ownerName: EditText
    private lateinit var contactSpinner: Spinner
    private lateinit var contactStatus: TextView
    private lateinit var editor: SecurePlaintextEditText
    private lateinit var countText: TextView
    private lateinit var encryptButton: Button
    private lateinit var pendingButton: Button
    private lateinit var passwordWarning: LinearLayout

    private var contacts: List<SecureContactSummary> = emptyList()
    private var requestedContactId: ByteArray? = null
    private var passwordAcknowledged = true
    private var cipherBoardImeSelected = false
    private var handoffToken: String? = null
    private var handoffScheduled = false
    private var imeObserverRegistered = false
    private var biometricPrompt: BiometricPrompt? = null
    private var pendingPromptAction: VaultUnlockAction.AuthenticationRequired? = null
    private var selectedPendingCount = 0
    private var selectedUncertainPendingCount = 0
    private var selectedPendingStateKnown = false
    private var standaloneReplyMode = false

    private val defaultImeObserver by lazy {
        object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                enforceImeTrust()
            }
        }
    }

    private val credentialLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val action = pendingPromptAction.also { pendingPromptAction = null } ?: return@registerForActivityResult
        if (result.resultCode == Activity.RESULT_OK) {
            runCatching { runtime.completePromptAuthentication(action) }
                .onSuccess(::handleUnlockAction)
                .onFailure(::showFailure)
        } else {
            vaultStatus.setText(R.string.secure_vault_unlock_cancelled)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.decorView.importantForContentCapture =
                View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        }
        runtime = SecureKeyboardRuntime.get()
        handoffToken = intent.getStringExtra(EXTRA_IME_HANDOFF_TOKEN)
            ?.takeIf(SecureImeBridge::activateComposer)
        requestedContactId = intent.getByteArrayExtra(EXTRA_REPLY_CONTACT_ID)
        standaloneReplyMode = requestedContactId != null && handoffToken == null
        intent.removeExtra(EXTRA_REPLY_CONTACT_ID)
        passwordAcknowledged = !intent.getBooleanExtra(EXTRA_HOST_IS_PASSWORD_FIELD, false)
        setContentView(buildContent())
        refreshRuntimeState()
    }

    override fun onProvideAssistData(data: Bundle) {
        data.clear()
    }

    override fun onProvideAssistContent(outContent: AssistContent) = Unit

    private fun buildContent(): View {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(24))
            ViewCompat.setImportantForAutofill(
                this,
                AUTOFILL_NO_EXCLUDE_DESCENDANTS,
            )
        }

        content.addView(TextView(this).apply {
            text = getString(R.string.secure_composer_title)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        content.addGap(6)
        content.addView(TextView(this).apply { setText(R.string.secure_composer_privacy_note) })
        content.addGap(12)

        imeWarning = TextView(this).apply {
            setText(R.string.secure_cipherboard_ime_required)
            visibility = View.GONE
        }
        content.addView(imeWarning)
        content.addGap(8)

        vaultStatus = TextView(this)
        content.addView(vaultStatus)
        content.addGap(8)
        content.addView(Button(this).apply {
            setText(R.string.secure_unlock_vault)
            setOnClickListener { requestVaultUnlock() }
        })

        passwordWarning = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = if (passwordAcknowledged) View.GONE else View.VISIBLE
            addView(TextView(this@SecureComposerActivity).apply {
                setText(R.string.secure_password_host_warning)
            })
            addView(Button(this@SecureComposerActivity).apply {
                setText(R.string.secure_password_host_continue)
                setOnClickListener {
                    passwordAcknowledged = true
                    passwordWarning.visibility = View.GONE
                    updatePendingCiphertext()
                }
            })
        }
        content.addGap(12)
        content.addView(passwordWarning)

        ownerSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(TextView(this@SecureComposerActivity).apply {
                setText(R.string.secure_create_identity_required)
            })
            ownerName = EditText(this@SecureComposerActivity).apply {
                hint = getString(R.string.secure_local_owner_name)
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
                    InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                isSaveEnabled = false
                ViewCompat.setImportantForAutofill(this, AUTOFILL_NO)
            }
            addView(ownerName, matchWidth())
            addView(Button(this@SecureComposerActivity).apply {
                setText(R.string.secure_create_identity)
                setOnClickListener { createOwner() }
            })
        }
        content.addView(ownerSection)
        content.addGap(12)

        content.addView(TextView(this).apply { setText(R.string.secure_recipient) })
        contactSpinner = Spinner(this).apply {
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    updateSelectedContact(position)
                }

                override fun onNothingSelected(parent: AdapterView<*>?) = updateSelectedContact(-1)
            }
        }
        content.addView(contactSpinner, matchWidth())
        contactStatus = TextView(this)
        content.addView(contactStatus)
        content.addGap(10)

        editor = SecurePlaintextEditText(this).apply {
            hint = getString(R.string.secure_message_hint)
            minLines = 5
            maxLines = 10
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
                EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_FULLSCREEN
            privateImeOptions = InputAttributes.CIPHERBOARD_SECURE_EDITOR_OPTION
            filters = arrayOf(Utf8ByteLimitFilter(::currentPlaintextLimitBytes) {
                contactStatus.setText(R.string.secure_message_too_large)
            })
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = updateCounts()
                override fun afterTextChanged(s: Editable?) = Unit
            })
        }
        content.addView(editor, matchWidth())
        countText = TextView(this)
        content.addView(countText)
        content.addGap(10)

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        encryptButton = Button(this).apply {
            setText(
                if (standaloneReplyMode) R.string.secure_encrypt_save_for_reply
                else R.string.secure_encrypt_and_insert,
            )
            setOnClickListener { encryptAndInsert() }
        }
        actions.addView(encryptButton, weighted())
        actions.addView(Button(this).apply {
            setText(R.string.secure_clear)
            setOnClickListener { clearPlaintext() }
        }, weighted())
        content.addView(actions, matchWidth())
        content.addView(Button(this).apply {
            setText(R.string.close_secure_composer)
            setOnClickListener { closeComposer() }
        }, matchWidth())

        pendingButton = Button(this).apply {
            visibility = View.GONE
            setOnClickListener { handlePendingCiphertext() }
        }
        content.addView(pendingButton, matchWidth())

        updateCounts()
        return ScrollView(this).apply {
            isFillViewport = true
            addView(content, matchWidth())
            ViewCompat.setOnApplyWindowInsetsListener(this) { view, insets ->
                val safeDrawing = insets.getInsets(
                    WindowInsetsCompat.Type.systemBars() or
                        WindowInsetsCompat.Type.displayCutout(),
                )
                val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
                view.setPadding(
                    safeDrawing.left,
                    safeDrawing.top,
                    safeDrawing.right,
                    maxOf(safeDrawing.bottom, ime.bottom),
                )
                insets
            }
        }
    }

    private fun requestVaultUnlock() {
        runCatching { runtime.prepareUnlock() }
            .onSuccess(::handleUnlockAction)
            .onFailure(::showFailure)
    }

    private fun handleUnlockAction(action: VaultUnlockAction) {
        when (action) {
            is VaultUnlockAction.Unlocked -> {
                vaultStatus.text = getString(
                    R.string.secure_vault_unlocked_level,
                    securityLevelLabel(action.protectionInfo.securityLevel),
                )
                refreshRuntimeState()
            }
            is VaultUnlockAction.AuthenticationRequired -> authenticate(action)
            is VaultUnlockAction.CryptoObjectAuthenticationRequired -> authenticate(action)
            is VaultUnlockAction.KeyInvalidated -> {
                vaultStatus.setText(R.string.secure_vault_key_invalidated)
                updateEditorEnabledState()
            }
        }
    }

    private fun authenticate(action: VaultUnlockAction.AuthenticationRequired) {
        if (action.requiresLegacyConfirmCredential) {
            val keyguard = getSystemService(KeyguardManager::class.java)
            val credentialIntent = keyguard?.createConfirmDeviceCredentialIntent(
                getString(R.string.secure_unlock_vault),
                getString(R.string.secure_unlock_vault_description),
            )
            if (credentialIntent == null) {
                showFailure(IllegalStateException("Device credential UI unavailable"))
                return
            }
            pendingPromptAction = action
            credentialLauncher.launch(credentialIntent)
            return
        }
        val prompt = newBiometricPrompt(
            onSuccess = { _ ->
                runCatching { runtime.completePromptAuthentication(action) }
                    .onSuccess(::handleUnlockAction)
                    .onFailure(::showFailure)
            },
        )
        biometricPrompt = prompt
        prompt.authenticate(promptInfo(action.allowedAuthenticators))
    }

    private fun authenticate(action: VaultUnlockAction.CryptoObjectAuthenticationRequired) {
        val cryptoObject = action.cryptoObject as? BiometricPrompt.CryptoObject
            ?: return showFailure(IllegalStateException("Invalid authentication object"))
        val prompt = newBiometricPrompt(
            onSuccess = { result ->
                val authenticatedCryptoObject = result.cryptoObject
                    ?: return@newBiometricPrompt showFailure(
                        IllegalStateException("Authentication returned no cryptographic object"),
                    )
                runCatching {
                    runtime.completeCryptoObjectAuthentication(action, authenticatedCryptoObject)
                }
                    .onSuccess(::handleUnlockAction)
                    .onFailure(::showFailure)
            },
        )
        biometricPrompt = prompt
        prompt.authenticate(promptInfo(action.allowedAuthenticators), cryptoObject)
    }

    private fun newBiometricPrompt(
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    ): BiometricPrompt = BiometricPrompt(
        this,
        ContextCompat.getMainExecutor(this),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess(result)

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                vaultStatus.setText(R.string.secure_vault_unlock_cancelled)
            }

            override fun onAuthenticationFailed() {
                vaultStatus.setText(R.string.secure_vault_unlock_failed)
            }
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

    private fun securityLevelLabel(level: KeystoreSecurityLevel): String = getString(
        when (level) {
            KeystoreSecurityLevel.STRONGBOX -> R.string.cipherboard_home_keystore_strongbox
            KeystoreSecurityLevel.TRUSTED_ENVIRONMENT -> R.string.cipherboard_home_keystore_tee
            KeystoreSecurityLevel.SOFTWARE -> R.string.cipherboard_home_keystore_software
            KeystoreSecurityLevel.UNKNOWN -> R.string.cipherboard_home_keystore_unknown
        },
    )

    private fun createOwner() {
        if (!enforceImeTrust()) return
        if (!runtime.isVaultUnlocked) return requestVaultUnlock()
        val name = ownerName.text?.toString()?.trim().orEmpty()
        if (name.isBlank()) {
            ownerName.error = getString(R.string.secure_local_name_required)
            return
        }
        runCatching { runtime.ensureOwner(name) }
            .onSuccess {
                ownerName.text?.clear()
                refreshRuntimeState()
            }
            .onFailure(::showFailure)
    }

    private fun refreshRuntimeState() {
        val unlocked = runtime.isVaultUnlocked
        if (!unlocked) {
            vaultStatus.setText(R.string.secure_vault_locked)
            contacts = emptyList()
            updateContacts()
            ownerSection.visibility = View.GONE
            updateEditorEnabledState()
            return
        }
        val owner = runCatching { runtime.owner() }.getOrElse {
            showFailure(it)
            null
        }
        ownerSection.visibility = if (owner == null) View.VISIBLE else View.GONE
        contacts = if (owner == null) emptyList() else runCatching { runtime.listContacts() }
            .getOrElse {
                showFailure(it)
                emptyList()
            }
        updateContacts()
        updatePendingCiphertext()
        updateEditorEnabledState()
    }

    private fun updateContacts() {
        val names = if (contacts.isEmpty()) {
            listOf(getString(R.string.secure_no_contacts))
        } else {
            contacts.map { it.localName }
        }
        contactSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, names)
        requestedContactId?.let { requested ->
            val selected = contacts.indexOfFirst { contact ->
                val candidate = contact.internalId()
                try {
                    candidate.contentEquals(requested)
                } finally {
                    candidate.fill(0)
                }
            }
            if (selected >= 0) contactSpinner.setSelection(selected)
            requested.fill(0)
            requestedContactId = null
        }
        updateSelectedContact(if (contacts.isEmpty()) -1 else contactSpinner.selectedItemPosition)
    }

    private fun updateSelectedContact(position: Int, refreshPending: Boolean = true) {
        val contact = contacts.getOrNull(position)
        contactStatus.text = if (::editor.isInitialized && !messageWithinSelectedLimit()) {
            getString(R.string.secure_message_too_large)
        } else when {
            contact == null -> getString(R.string.secure_pair_contact_first)
            contact.verificationStatus == ContactVerificationStatus.VERIFIED ->
                getString(R.string.secure_contact_verified)
            contact.verificationStatus == ContactVerificationStatus.KEY_CHANGED ->
                getString(R.string.secure_contact_key_changed)
            contact.verificationStatus == ContactVerificationStatus.SESSION_ERROR ->
                getString(R.string.secure_contact_session_error)
            contact.verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED ->
                getString(R.string.secure_contact_pairing_required)
            else -> getString(R.string.secure_contact_unverified)
        }
        if (refreshPending) updatePendingCiphertext() else updateEditorEnabledState()
    }

    private fun updateEditorEnabledState() {
        val usable = canComposeForSelectedContact() && selectedPendingStateKnown &&
            selectedPendingCount == 0 && selectedUncertainPendingCount == 0
        editor.isEnabled = usable
        if (::ownerName.isInitialized) ownerName.isEnabled = cipherBoardImeSelected && runtime.isVaultUnlocked
        encryptButton.isEnabled = usable && editor.text?.isNotEmpty() == true && messageWithinSelectedLimit()
    }

    private fun updateCounts() {
        if (!::countText.isInitialized || !::editor.isInitialized) return
        val characters = Character.codePointCount(editor.text, 0, editor.length())
        val utf8Estimate = estimateUtf8Bytes(editor.text)
        countText.text = messagePresentationEstimateText(
            characters = characters,
            plaintextBytes = utf8Estimate,
            presentation = currentMessagePresentation(),
        )
        if (!messageWithinSelectedLimit()) {
            contactStatus.setText(R.string.secure_message_too_large)
        } else {
            updateSelectedContact(contactSpinner.selectedItemPosition, refreshPending = false)
        }
        if (::encryptButton.isInitialized) updateEditorEnabledState()
    }

    private fun encryptAndInsert() {
        if (!enforceImeTrust()) return
        updatePendingCiphertext()
        if (!canComposeForSelectedContact() || !selectedPendingStateKnown ||
            selectedPendingCount != 0 || selectedUncertainPendingCount != 0
        ) {
            contactStatus.setText(R.string.secure_retry_pending_before_new_message)
            return
        }
        val contact = contacts.getOrNull(contactSpinner.selectedItemPosition) ?: return
        val plaintext = try {
            encodeUtf8(editor.text)
        } catch (_: Exception) {
            contactStatus.setText(R.string.secure_invalid_unicode)
            return
        }
        if (plaintext.isEmpty()) {
            plaintext.fill(0)
            return
        }
        if (plaintext.size > currentPlaintextLimitBytes()) {
            plaintext.fill(0)
            contactStatus.setText(R.string.secure_message_too_large)
            updateEditorEnabledState()
            return
        }
        val contactId = contact.internalId()
        try {
            runtime.encrypt(
                contactId,
                plaintext,
                presentation = currentMessagePresentation(),
            ).use { outbound ->
                clearPlaintext()
                if (scheduleImeHandoff(outbound)) {
                    finishAndRemoveTask()
                } else {
                    contactStatus.setText(R.string.secure_ciphertext_pending)
                    updatePendingCiphertext()
                }
            }
        } catch (error: Throwable) {
            plaintext.fill(0)
            showFailure(error)
        } finally {
            contactId.fill(0)
        }
    }

    private fun showFailure(error: Throwable) {
        vaultStatus.text = when ((error as? SecureRuntimeException)?.reason) {
            SecureRuntimeError.CONTACT_NOT_READY -> getString(R.string.secure_contact_not_ready)
            SecureRuntimeError.REPLAY -> getString(R.string.secure_message_replay)
            SecureRuntimeError.CORRUPT_STATE -> getString(R.string.secure_vault_corrupt)
            else -> getString(R.string.secure_operation_failed)
        }
        updateEditorEnabledState()
    }

    private fun updatePendingCiphertext() {
        if (!::pendingButton.isInitialized) return
        val selectedContact = contacts.getOrNull(contactSpinner.selectedItemPosition)
        val result = if (runtime.isVaultUnlocked && selectedContact != null) {
            val contactId = selectedContact.internalId()
            try {
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
                            PendingCiphertextCounts(ready, uncertain)
                        } finally {
                            pending.forEach(PreparedOutbound::close)
                        }
                    }
                }
            } finally {
                contactId.fill(0)
            }
        } else {
            null
        }
        selectedPendingStateKnown = result?.isSuccess == true
        val counts = result?.getOrDefault(PendingCiphertextCounts.EMPTY) ?: PendingCiphertextCounts.EMPTY
        selectedPendingCount = counts.ready
        selectedUncertainPendingCount = counts.uncertain
        val hasUncertain = selectedUncertainPendingCount > 0
        val canAct = selectedPendingStateKnown && if (hasUncertain) {
            canComposeForSelectedContact()
        } else {
            selectedPendingCount > 0 && canHandoffToSelectedContact()
        }
        pendingButton.visibility = if (canAct) View.VISIBLE else View.GONE
        pendingButton.isEnabled = canAct
        if (canAct) {
            if (hasUncertain) {
                pendingButton.setText(R.string.embedded_secure_acknowledge_uncertain)
                pendingButton.contentDescription =
                    getString(R.string.embedded_secure_acknowledge_uncertain_description)
                contactStatus.setText(R.string.embedded_secure_delivery_uncertain)
            } else {
                pendingButton.text = resources.getQuantityString(
                    R.plurals.secure_retry_pending_ciphertext,
                    selectedPendingCount,
                    selectedPendingCount,
                )
                pendingButton.contentDescription = pendingButton.text
                contactStatus.setText(R.string.secure_retry_pending_before_new_message)
            }
        }
        updateEditorEnabledState()
    }

    private fun handlePendingCiphertext() {
        if (selectedUncertainPendingCount > 0) acknowledgeUncertainDelivery()
        else retryPendingCiphertext()
    }

    private fun retryPendingCiphertext() {
        if (!runtime.isVaultUnlocked) return requestVaultUnlock()
        if (!enforceImeTrust()) return
        updatePendingCiphertext()
        if (!canHandoffToSelectedContact() || !selectedPendingStateKnown || selectedPendingCount == 0) return
        val contact = contacts.getOrNull(contactSpinner.selectedItemPosition) ?: return
        val contactId = contact.internalId()
        val pending = runCatching {
            runtime.pendingOutbound().let { candidates ->
                val selected = candidates.firstOrNull {
                    it.canAutomaticallyRetry && it.matchesContact(contactId)
                }
                candidates.filter { it !== selected }.forEach(PreparedOutbound::close)
                selected
            }
        }
            .getOrElse {
                contactId.fill(0)
                showFailure(it)
                return
            }
        contactId.fill(0)
        if (pending == null) {
            contactStatus.setText(R.string.secure_no_pending_for_contact)
            return updatePendingCiphertext()
        }
        try {
            if (scheduleImeHandoff(pending)) {
                finishAndRemoveTask()
            } else {
                contactStatus.setText(R.string.secure_ciphertext_pending)
            }
        } finally {
            pending.close()
        }
    }

    private fun acknowledgeUncertainDelivery() {
        if (!runtime.isVaultUnlocked) return requestVaultUnlock()
        if (!enforceImeTrust()) return
        val contactId = contacts.getOrNull(contactSpinner.selectedItemPosition)?.internalId() ?: return
        val pending = try {
            runtime.pendingOutbound().let { candidates ->
                val selected = candidates.firstOrNull {
                    !it.canAutomaticallyRetry && it.matchesContact(contactId)
                }
                candidates.filter { it !== selected }.forEach(PreparedOutbound::close)
                selected
            }
        } catch (error: Throwable) {
            showFailure(error)
            null
        } finally {
            contactId.fill(0)
        } ?: return
        try {
            val operationId = pending.operationId()
            val completed = try {
                runtime.completeOutbound(operationId)
            } finally {
                operationId.fill(0)
            }
            contactStatus.setText(
                if (completed) R.string.embedded_secure_uncertain_cleared
                else R.string.secure_operation_failed,
            )
        } catch (error: Throwable) {
            showFailure(error)
        } finally {
            pending.close()
            updatePendingCiphertext()
        }
    }

    private fun PreparedOutbound.matchesContact(contactId: ByteArray): Boolean {
        val pendingContactId = contactId()
        return try {
            pendingContactId.contentEquals(contactId)
        } finally {
            pendingContactId.fill(0)
        }
    }

    private fun canHandoffToSelectedContact(): Boolean {
        return secureHandoffAllowed(
            imeTrusted = cipherBoardImeSelected,
            passwordAcknowledged = passwordAcknowledged,
            hasLiveHandoffToken = handoffToken != null,
            vaultUnlocked = runtime.isVaultUnlocked,
            contactReady = selectedContactReady(),
        )
    }

    private fun canComposeForSelectedContact(): Boolean {
        return secureHandoffAllowed(
            imeTrusted = cipherBoardImeSelected,
            passwordAcknowledged = passwordAcknowledged,
            hasLiveHandoffToken = handoffToken != null || standaloneReplyMode,
            vaultUnlocked = runtime.isVaultUnlocked,
            contactReady = selectedContactReady(),
        )
    }

    private fun selectedContactReady(): Boolean {
        val contact = contacts.getOrNull(contactSpinner.selectedItemPosition)
        return contact != null && !contact.requiresRepairing && !contact.sessionError &&
            !contact.keyChanged && contact.verificationStatus != ContactVerificationStatus.PAIRING_REQUIRED
    }

    private fun scheduleImeHandoff(outbound: PreparedOutbound): Boolean {
        val token = handoffToken ?: return false
        if (!SecureImeBridge.arm(token, outbound)) return false
        handoffScheduled = true
        handoffToken = null
        return true
    }

    private fun enforceImeTrust(): Boolean {
        val trusted = SecureComposerImeTrust.isCipherBoardSelected(this)
        if (!trusted) clearPlaintext()
        cipherBoardImeSelected = trusted
        if (::imeWarning.isInitialized) imeWarning.visibility = if (trusted) View.GONE else View.VISIBLE
        if (::editor.isInitialized) updateEditorEnabledState()
        return trusted
    }

    private fun closeComposer() {
        handoffToken?.let(SecureImeBridge::cancelSession)
        handoffToken = null
        finishAndRemoveTask()
    }

    private fun clearPlaintext() {
        if (::editor.isInitialized) editor.clearAndForgetHistory()
        if (::ownerName.isInitialized) ownerName.text?.clear()
    }

    override fun onStart() {
        super.onStart()
        contentResolver.registerContentObserver(
            Settings.Secure.getUriFor(Settings.Secure.DEFAULT_INPUT_METHOD),
            false,
            defaultImeObserver,
        )
        imeObserverRegistered = true
        enforceImeTrust()
    }

    override fun onStop() {
        clearPlaintext()
        if (imeObserverRegistered) {
            contentResolver.unregisterContentObserver(defaultImeObserver)
            imeObserverRegistered = false
        }
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        enforceImeTrust()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) enforceImeTrust() else clearPlaintext()
    }

    override fun onDestroy() {
        biometricPrompt?.cancelAuthentication()
        clearPlaintext()
        contacts = emptyList()
        requestedContactId?.fill(0)
        requestedContactId = null
        if (!isChangingConfigurations && !handoffScheduled) {
            handoffToken?.let(SecureImeBridge::cancelSession)
        }
        handoffToken = null
        super.onDestroy()
    }

    private fun encodeUtf8(text: CharSequence): ByteArray {
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val capacity = ceil(text.length * encoder.maxBytesPerChar().toDouble()).toInt().coerceAtLeast(1)
        val buffer = ByteBuffer.allocate(capacity)
        return try {
            val chars = CharBuffer.wrap(text)
            encoder.encode(chars, buffer, true).throwException()
            encoder.flush(buffer).throwException()
            buffer.flip()
            ByteArray(buffer.remaining()).also(buffer::get)
        } finally {
            buffer.array().fill(0)
        }
    }

    private fun estimateUtf8Bytes(text: CharSequence): Int {
        var bytes = 0
        var index = 0
        while (index < text.length) {
            val codePoint = Character.codePointAt(text, index)
            bytes += when {
                codePoint <= 0x7f -> 1
                codePoint <= 0x7ff -> 2
                codePoint <= 0xffff -> 3
                else -> 4
            }
            index += Character.charCount(codePoint)
        }
        return bytes
    }

    private fun currentMessagePresentation(): TransportPresentation =
        MessagePresentationPreferences.read(this)

    private fun currentPlaintextLimitBytes(): Int =
        maximumPlaintextBytes(currentMessagePresentation())

    private fun messageWithinSelectedLimit(): Boolean =
        estimateUtf8Bytes(editor.text) <= currentPlaintextLimitBytes()

    private fun dp(value: Int): Int = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP,
        value.toFloat(),
        resources.displayMetrics,
    ).toInt()

    private fun matchWidth() = ViewGroup.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    private fun weighted() = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)

    private fun LinearLayout.addGap(heightDp: Int) = addView(View(context), matchWidth().apply {
        height = dp(heightDp)
    })

    companion object {
        const val EXTRA_HOST_IS_PASSWORD_FIELD = "org.cipherboard.extra.HOST_IS_PASSWORD_FIELD"
        const val EXTRA_REPLY_CONTACT_ID = "org.cipherboard.extra.REPLY_CONTACT_ID"
        const val EXTRA_IME_HANDOFF_TOKEN = "org.cipherboard.extra.IME_HANDOFF_TOKEN"
    }
}

private data class PendingCiphertextCounts(val ready: Int, val uncertain: Int) {
    companion object {
        val EMPTY = PendingCiphertextCounts(0, 0)
    }
}

internal class Utf8ByteLimitFilter(
    private val limitBytes: () -> Int,
    private val onRejected: () -> Unit = {},
) : InputFilter {
    override fun filter(
        source: CharSequence,
        start: Int,
        end: Int,
        dest: Spanned,
        dstart: Int,
        dend: Int,
    ): CharSequence? {
        val resultingBytes = utf8Length(dest, 0, dstart) + utf8Length(source, start, end) +
            utf8Length(dest, dend, dest.length)
        if (resultingBytes <= limitBytes()) return null
        onRejected()
        return dest.subSequence(dstart, dend)
    }

    private fun utf8Length(value: CharSequence, start: Int, end: Int): Long {
        var bytes = 0L
        var index = start
        while (index < end) {
            val first = value[index]
            val paired = Character.isHighSurrogate(first) && index + 1 < end &&
                Character.isLowSurrogate(value[index + 1])
            val codePoint = if (paired) Character.toCodePoint(first, value[index + 1]) else first.code
            bytes += when {
                codePoint <= 0x7f -> 1
                codePoint <= 0x7ff -> 2
                codePoint <= 0xffff -> 3
                else -> 4
            }
            index += if (paired) 2 else 1
        }
        return bytes
    }
}

/** Disables copy/cut/share actions and view-state persistence for the plaintext widget. */
@SuppressLint("WrongConstant")
internal class SecurePlaintextEditText(context: Context) : EditText(
    context,
    null,
    android.R.attr.editTextStyle,
    R.style.CipherBoardSecurePlaintextEditor,
) {
    init {
        isSaveEnabled = false
        ViewCompat.setImportantForAutofill(this, AUTOFILL_NO)
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO
        }
        isLongClickable = false
        setTextIsSelectable(false)
        customSelectionActionModeCallback = object : ActionMode.Callback {
            override fun onCreateActionMode(mode: ActionMode?, menu: Menu?): Boolean = false
            override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?): Boolean = false
            override fun onActionItemClicked(mode: ActionMode?, item: MenuItem?): Boolean = false
            override fun onDestroyActionMode(mode: ActionMode?) = Unit
        }
        if (Build.VERSION.SDK_INT >= 34) {
            setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
    }

    override fun onTextContextMenuItem(id: Int): Boolean = when (id) {
        android.R.id.copy,
        android.R.id.cut,
        android.R.id.shareText,
        android.R.id.undo,
        android.R.id.redo,
        -> false
        else -> super.onTextContextMenuItem(id)
    }

    override fun onKeyShortcut(keyCode: Int, event: KeyEvent): Boolean {
        if (event.isCtrlPressed && (keyCode == KeyEvent.KEYCODE_Z || keyCode == KeyEvent.KEYCODE_Y)) {
            return true
        }
        return super.onKeyShortcut(keyCode, event)
    }

    fun clearAndForgetHistory() {
        editableText?.clear()
        setText("", TextView.BufferType.EDITABLE)
        setSelection(0)
    }

    override fun onProvideStructure(structure: ViewStructure) {
        blockStructure(structure)
    }

    override fun onProvideAutofillStructure(structure: ViewStructure, flags: Int) {
        blockStructure(structure)
        if (Build.VERSION.SDK_INT >= 26) structure.setAutofillType(View.AUTOFILL_TYPE_NONE)
    }

    override fun onProvideContentCaptureStructure(structure: ViewStructure, flags: Int) {
        blockStructure(structure)
    }

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        if (!SecureComposerImeTrust.isCipherBoardSelected(context)) {
            editableText?.clear()
            return null
        }
        val connection = super.onCreateInputConnection(outAttrs)
        EditorInfoCompat.setInitialSurroundingText(outAttrs, "")
        outAttrs.initialSelStart = -1
        outAttrs.initialSelEnd = -1
        outAttrs.initialCapsMode = 0
        outAttrs.imeOptions = outAttrs.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
            EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_FULLSCREEN
        outAttrs.privateImeOptions = InputAttributes.CIPHERBOARD_SECURE_EDITOR_OPTION
        if (!SecureComposerImeTrust.isCipherBoardSelected(context)) {
            editableText?.clear()
            return null
        }
        return connection
    }

    private fun blockStructure(structure: ViewStructure) {
        structure.setClassName(javaClass.name)
        if (Build.VERSION.SDK_INT >= 26) structure.setDataIsSensitive(true)
        structure.setChildCount(0)
    }
}
