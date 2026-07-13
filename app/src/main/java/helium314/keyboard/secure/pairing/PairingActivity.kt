// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.pairing

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Bundle
import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.fragment.app.FragmentActivity
import androidx.camera.view.PreviewView
import helium314.keyboard.latin.R
import helium314.keyboard.secure.home.ContactDetailsNavigation
import org.cipherboard.pairing.PairingQrCodec
import org.cipherboard.pairing.PairingQrPayload
import org.cipherboard.pairing.PairingQrPayloadType
import org.cipherboard.pairing.PairingQrScannerController
import org.cipherboard.securekeyboard.runtime.PairingOffer
import org.cipherboard.securekeyboard.runtime.PairingResponse
import org.cipherboard.securekeyboard.runtime.PairingRuntimeError
import org.cipherboard.securekeyboard.runtime.PairingRuntimeException
import org.cipherboard.securekeyboard.runtime.PreparedPairingConfirmation
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securestorage.ContactVerificationStatus
import java.io.Closeable
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import kotlin.math.min

// Stable android.view.View autofill importance value, used with ViewCompat for API 23-25.
private const val AUTOFILL_NO_EXCLUDE_DESCENDANTS = 8
private const val AUTOFILL_NO = 2

/** In-person, two-QR pairing flow. QR and Safety Number screens are intentionally non-exported. */
@SuppressLint("WrongConstant")
class PairingActivity : FragmentActivity() {
    private lateinit var runtime: SecureKeyboardRuntime
    private lateinit var root: LinearLayout
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "cipherboard-pairing").apply { isDaemon = true }
    }

    private var scanner: PairingQrScannerController? = null
    private var expectedScanType: PairingQrPayloadType? = null
    private var pendingContactName: String? = null
    private var repairContactId: ByteArray? = null
    private var offer: PairingOffer? = null
    private var response: PairingResponse? = null
    private var preparedConfirmation: PreparedPairingConfirmation? = null
    private var qrBitmap: Bitmap? = null
    private var committed = false
    private var busy = false
    private val queuedPairingHandles: MutableSet<Closeable> =
        Collections.newSetFromMap(ConcurrentHashMap<Closeable, Boolean>())

    private val cameraPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            showScanner()
        } else if (offer != null) {
            renderOfferWithError(getString(R.string.cipherboard_pairing_camera_denied))
        } else {
            renderStart(getString(R.string.cipherboard_pairing_camera_denied))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        runtime = SecureKeyboardRuntime.get()
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            isSaveEnabled = false
            setPadding(dp(20), dp(16), dp(20), dp(20))
            ViewCompat.setImportantForAutofill(this, AUTOFILL_NO_EXCLUDE_DESCENDANTS)
        }
        setContentView(ScrollView(this).apply {
            isFillViewport = true
            addView(
                root,
                FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                ),
            )
        })

        val repairToken = intent.getStringExtra(EXTRA_REPAIR_TOKEN)
        intent.removeExtra(EXTRA_REPAIR_TOKEN)
        if (repairToken != null) {
            repairContactId = ContactDetailsNavigation.resolve(repairToken)
        }

        if (!runtime.isVaultUnlocked || runtime.owner() == null) {
            renderLocked()
            return
        }

        try {
            runtime.cancelActivePairings()
        } catch (error: Throwable) {
            renderStart(errorMessage(error))
            return
        }

        if (savedInstanceState != null) {
            // Pairing handles are intentionally never serialized into lifecycle state.
            renderStart(getString(R.string.cipherboard_pairing_interrupted))
        } else if (repairToken != null && repairContactId == null) {
            renderStart(getString(R.string.cipherboard_pairing_repair_unavailable))
        } else if (repairContactId != null) {
            prepareRepairStart()
        } else {
            renderStart()
        }
    }

    override fun onResume() {
        super.onResume()
        if (::runtime.isInitialized && !runtime.isVaultUnlocked && !busy && scanner == null) {
            closePairingHandles(cancelPending = false)
            renderLocked()
        }
    }

    override fun onStop() {
        if (!isChangingConfigurations && !isFinishing && !committed) {
            scanner?.close()
            scanner = null
            if (::runtime.isInitialized && runtime.isVaultUnlocked) cancelActivePairing()
            closePairingHandles(cancelPending = false)
            clearQrBitmap()
            finish()
        }
        super.onStop()
    }

    override fun onDestroy() {
        scanner?.close()
        scanner = null
        clearQrBitmap()
        if (isFinishing && !committed && ::runtime.isInitialized && runtime.isVaultUnlocked) {
            cancelActivePairing()
        }
        closePairingHandles(cancelPending = false)
        pendingContactName = null
        repairContactId?.fill(0)
        repairContactId = null
        worker.shutdownNow()
        closeQueuedPairingHandles()
        super.onDestroy()
    }

    private fun renderStart(error: String? = null) {
        if (repairContactId != null) return renderRepairStart(error)
        clearScreen()
        title(R.string.cipherboard_pairing_title)
        body(R.string.cipherboard_pairing_intro)
        error?.let(::errorText)

        val name = EditText(this).apply {
            hint = getString(R.string.cipherboard_pairing_contact_name)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            isSaveEnabled = false
            maxLines = 1
            ViewCompat.setImportantForAutofill(
                this,
                AUTOFILL_NO,
            )
            setText(pendingContactName.orEmpty())
        }
        root.addView(name, matchWrap(top = 20))
        body(R.string.cipherboard_pairing_name_private)

        command(R.string.cipherboard_pairing_show_offer, top = 20) {
            val localName = validatedName(name) ?: return@command
            pendingContactName = localName
            createOffer(localName)
        }
        command(R.string.cipherboard_pairing_scan_offer, top = 8) {
            val localName = validatedName(name) ?: return@command
            pendingContactName = localName
            startScanner(PairingQrPayloadType.OFFER)
        }
        secondaryCommand(R.string.cipherboard_pairing_close, top = 16) { finish() }
    }

    private fun prepareRepairStart() {
        val id = repairContactId?.copyOf() ?: return renderStart()
        try {
            val contact = runtime.contact(id)
            if (contact == null || !contact.requiresRepairing) {
                repairContactId?.fill(0)
                repairContactId = null
                renderStart(getString(R.string.cipherboard_pairing_repair_unavailable))
                return
            }
            pendingContactName = contact.localName
            renderRepairStart()
        } finally {
            id.fill(0)
        }
    }

    private fun renderRepairStart(error: String? = null) {
        clearScreen()
        title(R.string.cipherboard_pairing_repair_title)
        bodyText(
            getString(
                R.string.cipherboard_pairing_repair_description,
                pendingContactName.orEmpty(),
            ),
        )
        error?.let(::errorText)
        command(R.string.cipherboard_pairing_show_offer, top = 20) {
            createOffer(pendingContactName.orEmpty())
        }
        command(R.string.cipherboard_pairing_scan_offer, top = 8) {
            startScanner(PairingQrPayloadType.OFFER)
        }
        secondaryCommand(R.string.cipherboard_pairing_close, top = 16) { finish() }
    }

    private fun renderLocked() {
        clearScreen()
        title(R.string.cipherboard_pairing_vault_locked_title)
        body(R.string.cipherboard_pairing_vault_locked)
        command(R.string.cipherboard_pairing_close, top = 20) { finish() }
    }

    private fun createOffer(localName: String) {
        val repairId = repairContactId?.copyOf()
        runTask(
            work = {
                val created = try {
                    if (repairId == null) {
                        runtime.createPairingOffer(localName)
                    } else {
                        runtime.createRepairingOffer(repairId)
                    }
                } finally {
                    repairId?.fill(0)
                }
                try {
                    val bitmap = PairingQrCodec.encodeBitmap(created.qrPayload, qrSizePx())
                    CreatedOffer(created, bitmap)
                } catch (error: Throwable) {
                    cancelAndClose(created)
                    throw error
                }
            },
            success = { result ->
                offer = result.offer
                replaceQrBitmap(result.bitmap)
                renderOffer()
            },
        )
    }

    private fun renderOffer() {
        val current = offer ?: return renderStart(getString(R.string.cipherboard_pairing_failed))
        clearScreen(keepQr = true)
        title(R.string.cipherboard_pairing_offer_title)
        body(R.string.cipherboard_pairing_offer_description)
        showQr(R.string.cipherboard_pairing_offer_qr_description)
        bodyText(getString(R.string.cipherboard_pairing_expires, formatRemaining(current.expiresAtEpochMillis)))
        command(R.string.cipherboard_pairing_scan_response, top = 20) {
            startScanner(PairingQrPayloadType.RESPONSE)
        }
        secondaryCommand(R.string.cipherboard_pairing_cancel, top = 8) { cancelAndFinish() }
    }

    private fun startScanner(type: PairingQrPayloadType) {
        if (busy) return
        expectedScanType = type
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            showScanner()
        } else {
            cameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    private fun showScanner() {
        val expected = expectedScanType ?: return renderStart(getString(R.string.cipherboard_pairing_failed))
        clearScreen(keepQr = offer != null)
        title(
            if (expected == PairingQrPayloadType.OFFER) {
                R.string.cipherboard_pairing_scan_offer_title
            } else {
                R.string.cipherboard_pairing_scan_response_title
            },
        )
        body(R.string.cipherboard_pairing_scan_description)
        val preview = PreviewView(this).apply {
            contentDescription = getString(R.string.cipherboard_pairing_camera_preview)
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
        root.addView(preview, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(420)).apply {
            topMargin = dp(12)
            bottomMargin = dp(12)
        })
        secondaryCommand(R.string.cipherboard_pairing_cancel_scan) {
            scanner?.close()
            scanner = null
            if (offer != null) renderOffer() else renderStart()
        }

        scanner?.close()
        scanner = PairingQrScannerController(this).also { controller ->
            controller.bind(
                owner = this,
                previewView = preview,
                onResult = { payload -> handleScannedPayload(payload) },
                onFailure = {
                    controller.close()
                    scanner = null
                    if (offer != null) {
                        renderOfferWithError(getString(R.string.cipherboard_pairing_camera_failed))
                    } else {
                        renderStart(getString(R.string.cipherboard_pairing_camera_failed))
                    }
                },
            )
        }
    }

    private fun handleScannedPayload(payload: PairingQrPayload) {
        val expected = expectedScanType ?: return
        if (payload.type != expected) {
            errorText(
                getString(
                    if (expected == PairingQrPayloadType.OFFER) {
                        R.string.cipherboard_pairing_wrong_offer_qr
                    } else {
                        R.string.cipherboard_pairing_wrong_response_qr
                    },
                ),
            )
            return
        }
        scanner?.close()
        scanner = null
        expectedScanType = null
        if (expected == PairingQrPayloadType.OFFER) {
            respondToOffer(payload)
        } else {
            prepareResponse(payload)
        }
    }

    private fun respondToOffer(payload: PairingQrPayload) {
        val localName = pendingContactName
            ?: return renderStart(getString(R.string.cipherboard_pairing_name_required))
        val repairId = repairContactId?.copyOf()
        runTask(
            work = {
                val created = try {
                    if (repairId == null) {
                        runtime.respondToPairingOffer(localName, payload)
                    } else {
                        runtime.respondToPairingOfferForContact(repairId, payload)
                    }
                } finally {
                    repairId?.fill(0)
                }
                try {
                    val bitmap = PairingQrCodec.encodeBitmap(created.qrPayload, qrSizePx())
                    CreatedResponse(created, bitmap)
                } catch (error: Throwable) {
                    cancelAndClose(created)
                    throw error
                }
            },
            success = { result ->
                response = result.response
                replaceQrBitmap(result.bitmap)
                renderResponse()
            },
        )
    }

    private fun renderResponse(error: String? = null) {
        val current = response ?: return renderStart(getString(R.string.cipherboard_pairing_failed))
        clearScreen(keepQr = true)
        title(R.string.cipherboard_pairing_response_title)
        body(R.string.cipherboard_pairing_response_description)
        showQr(R.string.cipherboard_pairing_response_qr_description)
        error?.let(::errorText)
        if (current.identityChanged) showIdentityChangeWarning(current)
        showSafety(current.safetyNumber, current.safetyCode)
        bodyText(getString(R.string.cipherboard_pairing_expires, formatRemaining(current.expiresAtEpochMillis)))
        command(
            if (current.identityChanged) {
                R.string.cipherboard_pairing_confirm_changed_safety
            } else {
                R.string.cipherboard_pairing_confirm_safety
            },
            top = 20,
        ) { confirmResponder() }
        secondaryCommand(R.string.cipherboard_pairing_cancel, top = 8) { cancelAndFinish() }
    }

    private fun prepareResponse(payload: PairingQrPayload) {
        runTask(
            work = { runtime.preparePairingResponse(payload) },
            success = { prepared ->
                preparedConfirmation = prepared
                renderPreparedConfirmation()
            },
        )
    }

    private fun renderPreparedConfirmation(error: String? = null) {
        val prepared = preparedConfirmation
            ?: return renderStart(getString(R.string.cipherboard_pairing_failed))
        clearScreen()
        title(R.string.cipherboard_pairing_verify_title)
        body(R.string.cipherboard_pairing_verify_description)
        error?.let(::errorText)
        if (prepared.identityChanged) showIdentityChangeWarning(prepared)
        showSafety(prepared.safetyNumber, prepared.safetyCode)
        command(
            if (prepared.identityChanged) {
                R.string.cipherboard_pairing_confirm_changed_safety
            } else {
                R.string.cipherboard_pairing_confirm_safety
            },
            top = 20,
        ) { confirmInitiator() }
        secondaryCommand(R.string.cipherboard_pairing_cancel, top = 8) { cancelAndFinish() }
    }

    private fun showSafety(number: String, code: String) {
        label(R.string.cipherboard_pairing_safety_number, top = 20)
        valueText(number)
        label(R.string.cipherboard_pairing_safety_code, top = 16)
        valueText(code)
        body(R.string.cipherboard_pairing_safety_warning, top = 16)
    }

    private fun showIdentityChangeWarning(response: PairingResponse) {
        val previous = response.previousRemoteFingerprint()
        val replacement = response.remoteFingerprint()
        try {
            showIdentityChangeWarning(previous, replacement)
        } finally {
            previous.fill(0)
            replacement.fill(0)
        }
    }

    private fun showIdentityChangeWarning(prepared: PreparedPairingConfirmation) {
        val previous = prepared.previousRemoteFingerprint()
        val replacement = prepared.remoteFingerprint()
        try {
            showIdentityChangeWarning(previous, replacement)
        } finally {
            previous.fill(0)
            replacement.fill(0)
        }
    }

    private fun showIdentityChangeWarning(previous: ByteArray, replacement: ByteArray) {
        errorText(getString(R.string.cipherboard_pairing_identity_changed_warning))
        label(R.string.cipherboard_pairing_previous_fingerprint, top = 16)
        valueText(formatFingerprint(previous))
        label(R.string.cipherboard_pairing_replacement_fingerprint, top = 16)
        valueText(formatFingerprint(replacement))
        body(R.string.cipherboard_pairing_identity_changed_verification_required, top = 16)
    }

    private fun confirmInitiator() {
        val prepared = preparedConfirmation ?: return
        val pairingId = prepared.pairingId()
        preparedConfirmation = null
        queuedPairingHandles += prepared
        val submitted = runTask(
            work = {
                queuedPairingHandles.remove(prepared)
                runtime.confirmPairing(prepared)
            },
            success = { contact ->
                pairingId.fill(0)
                pairingSucceeded(contact.verificationStatus == ContactVerificationStatus.VERIFIED)
            },
            failure = {
                cancelPairingId(pairingId)
                closePairingHandles(cancelPending = false)
                renderStart(errorMessage(it))
            },
        )
        if (!submitted) {
            queuedPairingHandles.remove(prepared)
            prepared.close()
            pairingId.fill(0)
        }
    }

    private fun confirmResponder() {
        val current = response ?: return
        val pairingId = current.pairingId()
        response = null
        queuedPairingHandles += current
        val submitted = runTask(
            work = {
                queuedPairingHandles.remove(current)
                runtime.confirmPairing(current)
            },
            success = { contact ->
                pairingId.fill(0)
                pairingSucceeded(contact.verificationStatus == ContactVerificationStatus.VERIFIED)
            },
            failure = {
                cancelPairingId(pairingId)
                closePairingHandles(cancelPending = false)
                renderStart(errorMessage(it))
            },
        )
        if (!submitted) {
            queuedPairingHandles.remove(current)
            current.close()
            pairingId.fill(0)
        }
    }

    private fun pairingSucceeded(verified: Boolean) {
        committed = true
        closePairingHandles(cancelPending = false)
        clearScreen()
        title(
            if (verified) {
                R.string.cipherboard_pairing_complete_title
            } else {
                R.string.cipherboard_pairing_identity_changed_complete_title
            },
        )
        body(
            if (verified) {
                R.string.cipherboard_pairing_complete
            } else {
                R.string.cipherboard_pairing_identity_changed_complete
            },
        )
        command(R.string.cipherboard_pairing_done, top = 20) { finish() }
    }

    private fun renderOfferWithError(message: String) {
        renderOffer()
        errorText(message)
    }

    private fun cancelAndFinish() {
        cancelActivePairing()
        closePairingHandles(cancelPending = false)
        finish()
    }

    private fun cancelActivePairing() {
        val id = when {
            preparedConfirmation != null -> preparedConfirmation?.pairingId()
            response != null -> response?.pairingId()
            offer != null -> offer?.pairingId()
            else -> null
        } ?: return
        cancelPairingId(id)
    }

    private fun cancelPairingId(id: ByteArray) {
        try {
            runCatching { runtime.cancelPairing(id) }
        } finally {
            id.fill(0)
        }
    }

    private fun cancelAndClose(handle: PairingOffer) {
        val id = handle.pairingId()
        try {
            cancelPairingId(id)
        } finally {
            handle.close()
        }
    }

    private fun cancelAndClose(handle: PairingResponse) {
        val id = handle.pairingId()
        try {
            cancelPairingId(id)
        } finally {
            handle.close()
        }
    }

    private fun closePairingHandles(cancelPending: Boolean) {
        if (cancelPending) cancelActivePairing()
        closeQuietly(preparedConfirmation)
        preparedConfirmation = null
        closeQuietly(response)
        response = null
        closeQuietly(offer)
        offer = null
    }

    private fun closeQueuedPairingHandles() {
        queuedPairingHandles.forEach(::closeQuietly)
        queuedPairingHandles.clear()
    }

    private fun <T> runTask(
        work: () -> T,
        success: (T) -> Unit,
        failure: ((Throwable) -> Unit)? = null,
    ): Boolean {
        if (busy || worker.isShutdown) return false
        busy = true
        renderBusy()
        try {
            worker.execute {
                try {
                    val result = work()
                    runOnUiThread {
                        if (isFinishing || isDestroyed) {
                            when (result) {
                                is CreatedOffer -> cancelAndClose(result.offer)
                                is CreatedResponse -> cancelAndClose(result.response)
                            }
                            closeQuietly(result as? Closeable)
                        } else {
                            busy = false
                            success(result)
                        }
                    }
                } catch (error: Throwable) {
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) {
                            busy = false
                            if (failure != null) failure(error) else renderStart(errorMessage(error))
                        }
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            busy = false
            return false
        }
        return true
    }

    private fun renderBusy() {
        clearScreen()
        root.gravity = Gravity.CENTER
        root.addView(ProgressBar(this))
        body(R.string.cipherboard_pairing_working, top = 16)
    }

    private fun errorMessage(error: Throwable): String = when {
        !runtime.isVaultUnlocked -> getString(R.string.cipherboard_pairing_vault_locked)
        error is PairingRuntimeException && error.reason in setOf(
            PairingRuntimeError.INVALID_QR,
            PairingRuntimeError.WRONG_QR_TYPE,
            PairingRuntimeError.EXPIRED,
            PairingRuntimeError.NOT_FOUND,
            PairingRuntimeError.ALREADY_USED,
            PairingRuntimeError.TRANSCRIPT_MISMATCH,
        ) -> getString(R.string.cipherboard_pairing_invalid_or_expired)
        error is PairingRuntimeException && error.reason == PairingRuntimeError.CONTACT_ALREADY_EXISTS ->
            getString(R.string.cipherboard_pairing_contact_exists)
        error is IllegalArgumentException -> getString(R.string.cipherboard_pairing_invalid_or_expired)
        else -> getString(R.string.cipherboard_pairing_failed)
    }

    private fun validatedName(field: EditText): String? {
        val value = field.text?.toString()?.trim().orEmpty()
        if (value.isBlank()) {
            field.error = getString(R.string.cipherboard_pairing_name_required)
            return null
        }
        if (value.codePointCount(0, value.length) > 128 || value.any { Character.isISOControl(it) }) {
            field.error = getString(R.string.cipherboard_pairing_name_invalid)
            return null
        }
        return value
    }

    private fun clearScreen(keepQr: Boolean = false) {
        root.removeAllViews()
        root.gravity = Gravity.NO_GRAVITY
        if (!keepQr) clearQrBitmap()
    }

    private fun clearQrBitmap() {
        qrBitmap?.recycle()
        qrBitmap = null
    }

    private fun replaceQrBitmap(bitmap: Bitmap) {
        clearQrBitmap()
        qrBitmap = bitmap
    }

    private fun showQr(@StringRes description: Int) {
        val bitmap = qrBitmap ?: return
        root.addView(ImageView(this).apply {
            contentDescription = getString(description)
            adjustViewBounds = true
            scaleType = ImageView.ScaleType.FIT_CENTER
            setImageBitmap(bitmap)
        }, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(340)).apply {
            topMargin = dp(16)
        })
    }

    private fun title(@StringRes text: Int) {
        root.addView(TextView(this).apply {
            setText(text)
            textSize = 24f
            setTextColor(resolveColor(android.R.attr.textColorPrimary))
            ViewCompat.setAccessibilityHeading(this, true)
        }, matchWrap())
    }

    private fun body(@StringRes text: Int, top: Int = 8) = bodyText(getString(text), top)

    private fun bodyText(text: String, top: Int = 8) {
        root.addView(TextView(this).apply {
            this.text = text
            textSize = 16f
            setTextColor(resolveColor(android.R.attr.textColorSecondary))
        }, matchWrap(top))
    }

    private fun label(@StringRes text: Int, top: Int = 8) {
        root.addView(TextView(this).apply {
            setText(text)
            textSize = 14f
            setTextColor(resolveColor(android.R.attr.textColorSecondary))
        }, matchWrap(top))
    }

    private fun valueText(text: String) {
        root.addView(TextView(this).apply {
            this.text = text
            textSize = 20f
            setTextIsSelectable(false)
            ViewCompat.setImportantForAutofill(
                this,
                AUTOFILL_NO_EXCLUDE_DESCENDANTS,
            )
        }, matchWrap(4))
    }

    private fun errorText(text: String) {
        root.addView(TextView(this).apply {
            this.text = text
            textSize = 15f
            setTextColor(resolveColor(android.R.attr.colorError))
            announceForAccessibility(text)
        }, matchWrap(12))
    }

    private fun command(@StringRes text: Int, top: Int = 0, action: () -> Unit) {
        root.addView(Button(this).apply {
            setText(text)
            setOnClickListener { action() }
        }, matchWrap(top))
    }

    private fun secondaryCommand(@StringRes text: Int, top: Int = 0, action: () -> Unit) =
        command(text, top, action)

    private fun matchWrap(top: Int = 0) =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(top)
        }

    private fun qrSizePx(): Int {
        val metrics = resources.displayMetrics
        return (min(metrics.widthPixels, metrics.heightPixels) * 3 / 4).coerceIn(256, 1024)
    }

    private fun formatRemaining(expiresAtMillis: Long): String {
        val seconds = ((expiresAtMillis - System.currentTimeMillis()).coerceAtLeast(0) + 999) / 1000
        val minutes = (seconds + 59) / 60
        return resources.getQuantityString(R.plurals.cipherboard_pairing_minutes, minutes.toInt(), minutes)
    }

    private fun formatFingerprint(bytes: ByteArray): String {
        val compact = CharArray(bytes.size * 2)
        var offset = 0
        bytes.forEach { value ->
            val unsigned = value.toInt() and 0xff
            compact[offset++] = HEX[unsigned ushr 4]
            compact[offset++] = HEX[unsigned and 0x0f]
        }
        return try {
            compact.concatToString().chunked(8).joinToString(" ")
        } finally {
            compact.fill('\u0000')
        }
    }

    private fun resolveColor(attribute: Int): Int {
        val value = android.util.TypedValue()
        theme.resolveAttribute(attribute, value, true)
        return value.data
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun closeQuietly(closeable: Closeable?) {
        runCatching { closeable?.close() }
    }

    private class CreatedOffer(val offer: PairingOffer, val bitmap: Bitmap) : Closeable {
        override fun close() {
            offer.close()
            bitmap.recycle()
        }
    }

    private class CreatedResponse(val response: PairingResponse, val bitmap: Bitmap) : Closeable {
        override fun close() {
            response.close()
            bitmap.recycle()
        }
    }

    companion object {
        private const val EXTRA_REPAIR_TOKEN = "org.cipherboard.securekeyboard.REPAIR_TOKEN"
        private const val HEX = "0123456789ABCDEF"

        fun openRepair(context: Context, navigationToken: String) {
            context.startActivity(
                Intent(context, PairingActivity::class.java)
                    .putExtra(EXTRA_REPAIR_TOKEN, navigationToken),
            )
        }
    }
}
