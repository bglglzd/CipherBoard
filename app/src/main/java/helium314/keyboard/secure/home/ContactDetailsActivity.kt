// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import helium314.keyboard.secure.pairing.PairingActivity
import helium314.keyboard.latin.utils.BackButton
import helium314.keyboard.latin.utils.Theme
import org.cipherboard.securekeyboard.runtime.SecureContactSummary
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securestorage.ContactVerificationStatus
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Displays local contact metadata and performs explicit, crash-safe Vault mutations. */
class ContactDetailsActivity : FragmentActivity() {
    private lateinit var runtime: SecureKeyboardRuntime
    private val screenState = mutableStateOf<ContactScreenState>(ContactScreenState.Loading)
    private val dialog = mutableStateOf<ContactDialog?>(null)
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "cipherboard-contact").apply { isDaemon = true }
    }
    private var navigationToken: String? = null
    private var contactId: ByteArray? = null
    private var foreground = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        runtime = SecureKeyboardRuntime.get()
        navigationToken = intent.getStringExtra(EXTRA_NAVIGATION_TOKEN)
        contactId = navigationToken?.let(ContactDetailsNavigation::resolve)

        setContent {
            Theme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ContactDetailsScreen(
                        state = screenState.value,
                        dialog = dialog.value,
                        onBack = ::finish,
                        onRename = { dialog.value = ContactDialog.Rename(it) },
                        onExportFingerprint = { dialog.value = ContactDialog.ExportFingerprint(it) },
                        onVerify = { dialog.value = ContactDialog.Verify },
                        onDestroySession = { dialog.value = ContactDialog.DestroySession },
                        onDelete = { dialog.value = ContactDialog.Delete },
                        onRepair = { dialog.value = ContactDialog.Repair },
                        onDismissDialog = { dialog.value = null },
                        onConfirmRename = ::renameContact,
                        onConfirmExportFingerprint = ::exportFingerprint,
                        onConfirmVerify = ::verifyContact,
                        onConfirmDestroySession = { destroySession(openPairing = false) },
                        onConfirmDelete = ::deleteContact,
                        onConfirmRepair = { destroySession(openPairing = true) },
                    )
                }
            }
        }

        if (contactId == null) {
            screenState.value = ContactScreenState.Unavailable
        } else {
            refreshContact()
        }
    }

    override fun onResume() {
        super.onResume()
        foreground = true
        if (!::runtime.isInitialized || contactId == null) return
        if (!runtime.isVaultUnlocked) {
            screenState.value = ContactScreenState.Locked
        } else if (screenState.value !is ContactScreenState.Busy) {
            refreshContact()
        }
    }

    override fun onPause() {
        foreground = false
        clearSensitiveUi()
        super.onPause()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        contactId?.fill(0)
        contactId = null
        clearSensitiveUi()
        if (isFinishing) ContactDetailsNavigation.release(navigationToken)
        navigationToken = null
        super.onDestroy()
    }

    private fun refreshContact() {
        if (!runtime.isVaultUnlocked) {
            screenState.value = ContactScreenState.Locked
            return
        }
        runContactTask(
            work = { id -> runtime.contact(id) },
            success = { summary ->
                screenState.value = summary?.let { ContactScreenState.Ready(it.toUiModel()) }
                    ?: ContactScreenState.Unavailable
            },
        )
    }

    private fun renameContact(name: String) {
        dialog.value = null
        val normalized = name.trim()
        if (normalized.isEmpty()) {
            showCurrentError(R.string.cipherboard_contact_name_required)
            return
        }
        runMutation { id -> runtime.renameContact(id, normalized) }
    }

    private fun verifyContact() {
        dialog.value = null
        val ready = screenState.value as? ContactScreenState.Ready ?: return
        if (ready.contact.status == ContactDetailsStatus.VERIFIED) {
            Toast.makeText(this, R.string.cipherboard_contact_safety_rechecked, Toast.LENGTH_SHORT).show()
            return
        }
        runMutation { id ->
            runtime.verifyContact(
                id,
                ready.contact.fingerprint,
                ready.contact.safetyNumber,
                ready.contact.safetyCode,
            )
        }
    }

    private fun exportFingerprint(fingerprint: String) {
        dialog.value = null
        val chooser = Intent.createChooser(
            createFingerprintExportIntent(fingerprint),
            getString(R.string.cipherboard_contact_export_fingerprint_chooser),
        )
        runCatching { startActivity(chooser) }.onFailure {
            showCurrentError(R.string.cipherboard_contact_export_fingerprint_failed)
        }
    }

    private fun destroySession(openPairing: Boolean) {
        dialog.value = null
        runContactTask(
            work = { id -> runtime.destroyContactSession(id) },
            success = { summary ->
                screenState.value = ContactScreenState.Ready(summary.toUiModel())
                if (openPairing) openPairing()
            },
        )
    }

    private fun deleteContact() {
        dialog.value = null
        runContactTask(
            work = { id -> runtime.deleteContact(id) },
            success = { deleted ->
                if (deleted) {
                    ContactDetailsNavigation.release(navigationToken)
                    navigationToken = null
                    contactId?.fill(0)
                    contactId = null
                    finish()
                } else {
                    screenState.value = ContactScreenState.Unavailable
                }
            },
        )
    }

    private fun runMutation(mutation: (ByteArray) -> SecureContactSummary) {
        runContactTask(
            work = mutation,
            success = { screenState.value = ContactScreenState.Ready(it.toUiModel()) },
        )
    }

    private fun <T> runContactTask(work: (ByteArray) -> T, success: (T) -> Unit) {
        if (!runtime.isVaultUnlocked) {
            screenState.value = ContactScreenState.Locked
            return
        }
        val id = contactId?.copyOf() ?: run {
            screenState.value = ContactScreenState.Unavailable
            return
        }
        val previous = (screenState.value as? ContactScreenState.Ready)?.contact
        screenState.value = ContactScreenState.Busy(previous)
        worker.execute {
            val result = runCatching { work(id) }
            id.fill(0)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (!foreground) {
                    screenState.value = ContactScreenState.Loading
                    return@runOnUiThread
                }
                result.onSuccess(success).onFailure {
                    screenState.value = previous?.let {
                        ContactScreenState.Ready(
                            it,
                            getString(R.string.cipherboard_contact_operation_failed),
                        )
                    } ?: ContactScreenState.Unavailable
                }
            }
        }
    }

    private fun showCurrentError(message: Int) {
        val ready = screenState.value as? ContactScreenState.Ready ?: return
        screenState.value = ready.copy(error = getString(message))
    }

    private fun openPairing() {
        val token = navigationToken ?: return
        PairingActivity.openRepair(this, token)
    }

    private fun clearSensitiveUi() {
        dialog.value = null
        if (screenState.value is ContactScreenState.Ready || screenState.value is ContactScreenState.Busy) {
            screenState.value = if (::runtime.isInitialized && runtime.isVaultUnlocked) {
                ContactScreenState.Loading
            } else {
                ContactScreenState.Locked
            }
        }
    }

    private fun SecureContactSummary.toUiModel(): ContactDetailsUiModel {
        val fingerprint = identityFingerprint()
        return try {
            ContactDetailsUiModel(
                localName = localName,
                status = toStatus(),
                fingerprint = formatFingerprint(fingerprint),
                safetyNumber = safetyNumber,
                safetyCode = safetyCode,
                pairedAt = formatDate(pairedAtEpochMillis),
                lastActiveAt = formatDate(lastActiveAtEpochMillis),
                protocolVersion = protocolVersion,
            )
        } finally {
            fingerprint.fill(0)
        }
    }

    private fun SecureContactSummary.toStatus(): ContactDetailsStatus = when {
        keyChanged || verificationStatus == ContactVerificationStatus.KEY_CHANGED -> ContactDetailsStatus.KEY_CHANGED
        sessionError || verificationStatus == ContactVerificationStatus.SESSION_ERROR -> ContactDetailsStatus.SESSION_ERROR
        requiresRepairing || verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED -> ContactDetailsStatus.PAIRING_REQUIRED
        verificationStatus == ContactVerificationStatus.VERIFIED -> ContactDetailsStatus.VERIFIED
        else -> ContactDetailsStatus.UNVERIFIED
    }

    private fun formatDate(epochMillis: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(epochMillis))

    companion object {
        private const val EXTRA_NAVIGATION_TOKEN = "org.cipherboard.securekeyboard.CONTACT_TOKEN"
        private const val HEX = "0123456789ABCDEF"

        fun open(context: Context, navigationToken: String) {
            context.startActivity(
                Intent(context, ContactDetailsActivity::class.java)
                    .putExtra(EXTRA_NAVIGATION_TOKEN, navigationToken),
            )
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
        internal fun createFingerprintExportIntent(fingerprint: String): Intent {
            require(fingerprint.isNotBlank() && fingerprint.length <= 256)
            return Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, fingerprint)
            }
        }
    }
}

private sealed interface ContactScreenState {
    data object Loading : ContactScreenState
    data object Locked : ContactScreenState
    data object Unavailable : ContactScreenState
    data class Busy(val contact: ContactDetailsUiModel?) : ContactScreenState
    data class Ready(val contact: ContactDetailsUiModel, val error: String? = null) : ContactScreenState
}

private data class ContactDetailsUiModel(
    val localName: String,
    val status: ContactDetailsStatus,
    val fingerprint: String,
    val safetyNumber: String,
    val safetyCode: String,
    val pairedAt: String,
    val lastActiveAt: String,
    val protocolVersion: Int,
)

private enum class ContactDetailsStatus { VERIFIED, UNVERIFIED, KEY_CHANGED, PAIRING_REQUIRED, SESSION_ERROR }
private sealed interface ContactDialog {
    data class Rename(val currentName: String) : ContactDialog
    data class ExportFingerprint(val fingerprint: String) : ContactDialog
    data object Verify : ContactDialog
    data object DestroySession : ContactDialog
    data object Delete : ContactDialog
    data object Repair : ContactDialog
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactDetailsScreen(
    state: ContactScreenState,
    dialog: ContactDialog?,
    onBack: () -> Unit,
    onRename: (String) -> Unit,
    onExportFingerprint: (String) -> Unit,
    onVerify: () -> Unit,
    onDestroySession: () -> Unit,
    onDelete: () -> Unit,
    onRepair: () -> Unit,
    onDismissDialog: () -> Unit,
    onConfirmRename: (String) -> Unit,
    onConfirmExportFingerprint: (String) -> Unit,
    onConfirmVerify: () -> Unit,
    onConfirmDestroySession: () -> Unit,
    onConfirmDelete: () -> Unit,
    onConfirmRepair: () -> Unit,
) {
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cipherboard_contact_title)) },
                navigationIcon = { BackButton(onBack) },
                windowInsets = WindowInsets(0),
            )
        },
    ) { padding ->
        when (state) {
            ContactScreenState.Loading -> CenteredMessage(padding, loading = true)
            ContactScreenState.Locked -> CenteredMessage(
                padding,
                text = stringResource(R.string.cipherboard_contact_vault_locked),
            )
            ContactScreenState.Unavailable -> CenteredMessage(
                padding,
                text = stringResource(R.string.cipherboard_contact_unavailable),
            )
            is ContactScreenState.Busy -> state.contact?.let {
                ContactContent(
                    it,
                    null,
                    padding,
                    true,
                    onRename,
                    onExportFingerprint,
                    onVerify,
                    onDestroySession,
                    onDelete,
                    onRepair,
                )
            } ?: CenteredMessage(padding, loading = true)
            is ContactScreenState.Ready -> ContactContent(
                state.contact,
                state.error,
                padding,
                false,
                onRename,
                onExportFingerprint,
                onVerify,
                onDestroySession,
                onDelete,
                onRepair,
            )
        }
    }

    dialog?.let {
        ContactActionDialog(
            dialog = it,
            onDismiss = onDismissDialog,
            onRename = onConfirmRename,
            onExportFingerprint = onConfirmExportFingerprint,
            onVerify = onConfirmVerify,
            onDestroySession = onConfirmDestroySession,
            onDelete = onConfirmDelete,
            onRepair = onConfirmRepair,
        )
    }
}

@Composable
private fun CenteredMessage(padding: PaddingValues, text: String? = null, loading: Boolean = false) {
    Column(
        modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (loading) CircularProgressIndicator()
        text?.let {
            Text(it, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ContactContent(
    contact: ContactDetailsUiModel,
    error: String?,
    padding: PaddingValues,
    busy: Boolean,
    onRename: (String) -> Unit,
    onExportFingerprint: (String) -> Unit,
    onVerify: () -> Unit,
    onDestroySession: () -> Unit,
    onDelete: () -> Unit,
    onRepair: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(bottom = 28.dp),
    ) {
        item {
            Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp)) {
                Text(contact.localName, style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(6.dp))
                ContactStatusText(contact.status)
                if (contact.status == ContactDetailsStatus.KEY_CHANGED) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        stringResource(R.string.cipherboard_contact_key_changed_warning),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                error?.let {
                    Spacer(Modifier.height(12.dp))
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
                Spacer(Modifier.height(14.dp))
                OutlinedButton(
                    onClick = { onRename(contact.localName) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.cipherboard_contact_rename))
                }
            }
            HorizontalDivider()
        }
        item {
            DetailSection(R.string.cipherboard_contact_identity_fingerprint, contact.fingerprint, monospace = true)
            Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp)) {
                OutlinedButton(
                    onClick = { onExportFingerprint(contact.fingerprint) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.cipherboard_contact_export_fingerprint))
                }
            }
            DetailSection(R.string.cipherboard_contact_safety_number, contact.safetyNumber, monospace = true)
            DetailSection(R.string.cipherboard_contact_safety_code, contact.safetyCode, monospace = true)
            Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp)) {
                Button(
                    onClick = onVerify,
                    enabled = !busy && contact.status in setOf(
                        ContactDetailsStatus.UNVERIFIED,
                        ContactDetailsStatus.VERIFIED,
                        ContactDetailsStatus.KEY_CHANGED,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        stringResource(
                            when (contact.status) {
                                ContactDetailsStatus.VERIFIED -> R.string.cipherboard_contact_recheck_safety
                                ContactDetailsStatus.KEY_CHANGED -> R.string.cipherboard_contact_trust_changed_key
                                else -> R.string.cipherboard_contact_mark_verified
                            },
                        ),
                    )
                }
                Text(
                    stringResource(R.string.cipherboard_contact_verify_in_person),
                    modifier = Modifier.padding(top = 8.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Spacer(Modifier.height(18.dp))
            HorizontalDivider()
        }
        item {
            DetailSection(R.string.cipherboard_contact_paired_at, contact.pairedAt)
            DetailSection(R.string.cipherboard_contact_last_active, contact.lastActiveAt)
            DetailSection(R.string.cipherboard_contact_protocol, contact.protocolVersion.toString())
            HorizontalDivider()
        }
        item {
            Column(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedButton(onClick = onRepair, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.cipherboard_contact_repair))
                }
                OutlinedButton(onClick = onDestroySession, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.cipherboard_contact_destroy_session))
                }
                OutlinedButton(
                    onClick = onDelete,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) {
                    Text(stringResource(R.string.cipherboard_contact_delete))
                }
            }
        }
    }
}

@Composable
private fun ContactStatusText(status: ContactDetailsStatus) {
    val label = when (status) {
        ContactDetailsStatus.VERIFIED -> R.string.cipherboard_home_status_verified
        ContactDetailsStatus.UNVERIFIED -> R.string.cipherboard_home_status_unverified
        ContactDetailsStatus.KEY_CHANGED -> R.string.cipherboard_home_status_key_changed
        ContactDetailsStatus.PAIRING_REQUIRED -> R.string.cipherboard_home_status_pairing_required
        ContactDetailsStatus.SESSION_ERROR -> R.string.cipherboard_home_status_session_error
    }
    Text(
        stringResource(label),
        color = when (status) {
            ContactDetailsStatus.VERIFIED -> MaterialTheme.colorScheme.primary
            ContactDetailsStatus.UNVERIFIED -> MaterialTheme.colorScheme.onSurfaceVariant
            else -> MaterialTheme.colorScheme.error
        },
        style = MaterialTheme.typography.labelLarge,
    )
}

@Composable
private fun DetailSection(label: Int, value: String, monospace: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
        Text(stringResource(label), style = MaterialTheme.typography.labelLarge)
        Text(
            value,
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
    }
}

@Composable
private fun ContactActionDialog(
    dialog: ContactDialog,
    onDismiss: () -> Unit,
    onRename: (String) -> Unit,
    onExportFingerprint: (String) -> Unit,
    onVerify: () -> Unit,
    onDestroySession: () -> Unit,
    onDelete: () -> Unit,
    onRepair: () -> Unit,
) {
    var editedName by remember(dialog) {
        mutableStateOf((dialog as? ContactDialog.Rename)?.currentName.orEmpty())
    }
    val title = when (dialog) {
        is ContactDialog.Rename -> R.string.cipherboard_contact_rename
        is ContactDialog.ExportFingerprint -> R.string.cipherboard_contact_export_fingerprint
        ContactDialog.Verify -> R.string.cipherboard_contact_verify_title
        ContactDialog.DestroySession -> R.string.cipherboard_contact_destroy_session
        ContactDialog.Delete -> R.string.cipherboard_contact_delete
        ContactDialog.Repair -> R.string.cipherboard_contact_repair
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(title)) },
        text = {
            if (dialog is ContactDialog.Rename) {
                OutlinedTextField(
                    value = editedName,
                    onValueChange = { editedName = it },
                    label = { Text(stringResource(R.string.cipherboard_contact_local_name)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done,
                    ),
                )
            } else {
                Text(
                    stringResource(
                        when (dialog) {
                            ContactDialog.Verify -> R.string.cipherboard_contact_verify_confirmation
                            ContactDialog.DestroySession -> R.string.cipherboard_contact_destroy_confirmation
                            ContactDialog.Delete -> R.string.cipherboard_contact_delete_confirmation
                            ContactDialog.Repair -> R.string.cipherboard_contact_repair_confirmation
                            is ContactDialog.ExportFingerprint ->
                                R.string.cipherboard_contact_export_fingerprint_confirmation
                            is ContactDialog.Rename -> error("handled above")
                        },
                    ),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    when (dialog) {
                        is ContactDialog.Rename -> onRename(editedName)
                        is ContactDialog.ExportFingerprint -> onExportFingerprint(dialog.fingerprint)
                        ContactDialog.Verify -> onVerify()
                        ContactDialog.DestroySession -> onDestroySession()
                        ContactDialog.Delete -> onDelete()
                        ContactDialog.Repair -> onRepair()
                    }
                },
                enabled = dialog !is ContactDialog.Rename || editedName.isNotBlank(),
            ) {
                Text(
                    stringResource(
                        when (dialog) {
                            is ContactDialog.Rename -> R.string.cipherboard_contact_save
                            is ContactDialog.ExportFingerprint ->
                                R.string.cipherboard_contact_export_fingerprint_action
                            ContactDialog.Verify -> R.string.cipherboard_contact_confirm_compared
                            ContactDialog.DestroySession -> R.string.cipherboard_contact_destroy
                            ContactDialog.Delete -> R.string.cipherboard_contact_delete_action
                            ContactDialog.Repair -> R.string.cipherboard_contact_continue
                        },
                    ),
                    color = if (dialog == ContactDialog.Delete) {
                        MaterialTheme.colorScheme.error
                    } else {
                        androidx.compose.ui.graphics.Color.Unspecified
                    },
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.cancel)) }
        },
    )
}
