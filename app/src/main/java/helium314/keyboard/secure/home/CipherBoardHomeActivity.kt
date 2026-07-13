// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.app.Activity
import android.app.KeyguardManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import helium314.keyboard.latin.utils.Theme
import helium314.keyboard.settings.SettingsActivity
import org.cipherboard.securekeyboard.runtime.OwnerIdentitySummary
import org.cipherboard.securekeyboard.runtime.SecureContactSummary
import org.cipherboard.securekeyboard.runtime.SecureKeyboardRuntime
import org.cipherboard.securekeyboard.runtime.VaultUnlockAction
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.KeystoreSecurityLevel

/** Launcher dashboard for local identity, contacts, Vault state, and keyboard settings. */
class CipherBoardHomeActivity : FragmentActivity() {
    private lateinit var runtime: SecureKeyboardRuntime
    private val screenState = mutableStateOf<HomeScreenState>(HomeScreenState.Loading)
    private val showInvalidatedResetConfirmation = mutableStateOf(false)
    private var biometricPrompt: BiometricPrompt? = null
    private var pendingCredentialAction: VaultUnlockAction.AuthenticationRequired? = null

    private val credentialLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val action = pendingCredentialAction.also { pendingCredentialAction = null }
            ?: return@registerForActivityResult
        if (result.resultCode == Activity.RESULT_OK) {
            runCatching { runtime.completePromptAuthentication(action) }
                .onSuccess(::handleUnlockAction)
                .onFailure { showError(R.string.cipherboard_home_unlock_failed) }
        } else {
            showError(R.string.cipherboard_home_unlock_cancelled)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        runtime = SecureKeyboardRuntime.get()
        setContent {
            Theme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    HomeScreen(
                        state = screenState.value,
                        onUnlock = ::requestVaultUnlock,
                        onCreateIdentity = ::createIdentity,
                        onAddContact = ::openPairing,
                        onOpenContact = ::openContact,
                        onKeyboardSettings = ::openKeyboardSettings,
                        onVaultSettings = ::openVaultSettings,
                        onLockVault = ::lockVault,
                        onSecurity = ::openSecurity,
                        onLicenses = ::openLicenses,
                        showInvalidatedResetConfirmation = showInvalidatedResetConfirmation.value,
                        onRequestInvalidatedReset = { showInvalidatedResetConfirmation.value = true },
                        onDismissInvalidatedReset = { showInvalidatedResetConfirmation.value = false },
                        onConfirmInvalidatedReset = ::resetInvalidatedVault,
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshState()
    }

    override fun onDestroy() {
        releaseContactTokens(screenState.value)
        super.onDestroy()
    }

    private fun requestVaultUnlock() {
        screenState.value = HomeScreenState.Loading
        runCatching { runtime.prepareUnlock() }
            .onSuccess(::handleUnlockAction)
            .onFailure { showError(R.string.cipherboard_home_unlock_failed) }
    }

    private fun handleUnlockAction(action: VaultUnlockAction) {
        when (action) {
            is VaultUnlockAction.Unlocked -> refreshState(securityLevelLabel(action.protectionInfo.securityLevel))
            is VaultUnlockAction.AuthenticationRequired -> authenticate(action)
            is VaultUnlockAction.CryptoObjectAuthenticationRequired -> authenticate(action)
            is VaultUnlockAction.KeyInvalidated -> {
                releaseContactTokens(screenState.value)
                screenState.value = HomeScreenState.Locked(
                    getString(R.string.cipherboard_home_key_invalidated),
                    isCritical = true,
                    canResetInvalidatedVault = true,
                )
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
                showError(R.string.cipherboard_home_device_lock_required)
                return
            }
            pendingCredentialAction = action
            credentialLauncher.launch(credentialIntent)
            return
        }

        val prompt = newBiometricPrompt { _ ->
            runCatching { runtime.completePromptAuthentication(action) }
                .onSuccess(::handleUnlockAction)
                .onFailure { showError(R.string.cipherboard_home_unlock_failed) }
        }
        biometricPrompt = prompt
        prompt.authenticate(promptInfo(action.allowedAuthenticators))
    }

    private fun authenticate(action: VaultUnlockAction.CryptoObjectAuthenticationRequired) {
        val cryptoObject = action.cryptoObject as? BiometricPrompt.CryptoObject
        if (cryptoObject == null) {
            showError(R.string.cipherboard_home_unlock_failed)
            return
        }
        val prompt = newBiometricPrompt { result ->
            val authenticatedCryptoObject = result.cryptoObject
            if (authenticatedCryptoObject == null) {
                showError(R.string.cipherboard_home_unlock_failed)
                return@newBiometricPrompt
            }
            runCatching {
                runtime.completeCryptoObjectAuthentication(action, authenticatedCryptoObject)
            }
                .onSuccess(::handleUnlockAction)
                .onFailure { showError(R.string.cipherboard_home_unlock_failed) }
        }
        biometricPrompt = prompt
        prompt.authenticate(promptInfo(action.allowedAuthenticators), cryptoObject)
    }

    private fun newBiometricPrompt(
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    ): BiometricPrompt = BiometricPrompt(
        this,
        ContextCompat.getMainExecutor(this),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onSuccess(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                showError(R.string.cipherboard_home_unlock_cancelled)
            }

            override fun onAuthenticationFailed() {
                showError(R.string.cipherboard_home_unlock_failed)
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

    private fun createIdentity(localName: String) {
        if (!runtime.isVaultUnlocked) {
            requestVaultUnlock()
            return
        }
        val trimmedName = localName.trim()
        if (trimmedName.isEmpty()) {
            screenState.value = HomeScreenState.IdentityRequired(
                error = getString(R.string.cipherboard_home_local_name_required),
            )
            return
        }
        screenState.value = HomeScreenState.Loading
        runCatching { runtime.ensureOwner(trimmedName) }
            .onSuccess { refreshState() }
            .onFailure {
                screenState.value = HomeScreenState.IdentityRequired(
                    error = getString(R.string.cipherboard_home_identity_failed),
                )
            }
    }

    private fun refreshState(securityLevel: String? = null) {
        if (!runtime.isVaultUnlocked) {
            releaseContactTokens(screenState.value)
            screenState.value = HomeScreenState.Locked()
            return
        }
        runCatching {
            val owner = runtime.owner()
            if (owner == null) {
                HomeScreenState.IdentityRequired()
            } else {
                HomeScreenState.Ready(
                    owner = owner.toUiModel(),
                    contacts = runtime.listContacts().map { it.toUiModel() },
                    securityLevel = securityLevel,
                )
            }
        }.onSuccess {
            releaseContactTokens(screenState.value)
            screenState.value = it
        }
            .onFailure { showError(R.string.cipherboard_home_vault_read_failed) }
    }

    private fun lockVault() {
        biometricPrompt?.cancelAuthentication()
        biometricPrompt = null
        pendingCredentialAction = null
        runtime.lockVault()
        releaseContactTokens(screenState.value)
        screenState.value = HomeScreenState.Locked()
    }

    private fun resetInvalidatedVault() {
        showInvalidatedResetConfirmation.value = false
        screenState.value = HomeScreenState.Loading
        runCatching { runtime.resetInvalidatedVault() }
            .onSuccess { requestVaultUnlock() }
            .onFailure {
                screenState.value = HomeScreenState.Locked(
                    getString(R.string.cipherboard_home_reset_failed),
                    isCritical = true,
                    canResetInvalidatedVault = true,
                )
            }
    }

    private fun openPairing() {
        try {
            startActivity(Intent().setClassName(this, PAIRING_ACTIVITY_CLASS))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, R.string.cipherboard_home_pairing_unavailable, Toast.LENGTH_SHORT).show()
        }
    }

    private fun openKeyboardSettings() {
        startActivity(Intent(this, SettingsActivity::class.java))
    }

    private fun openVaultSettings() {
        startActivity(Intent(this, VaultSettingsActivity::class.java))
    }

    private fun openContact(contact: ContactUiModel) {
        ContactDetailsActivity.open(this, contact.navigationToken)
    }

    private fun openSecurity() {
        startActivity(Intent(this, SecurityInfoActivity::class.java))
    }

    private fun openLicenses() {
        startActivity(Intent(this, LicenseInfoActivity::class.java))
    }

    private fun showError(message: Int) {
        releaseContactTokens(screenState.value)
        screenState.value = HomeScreenState.Locked(getString(message), isCritical = false)
    }

    private fun securityLevelLabel(level: KeystoreSecurityLevel): String = getString(
        when (level) {
            KeystoreSecurityLevel.STRONGBOX -> R.string.cipherboard_home_keystore_strongbox
            KeystoreSecurityLevel.TRUSTED_ENVIRONMENT -> R.string.cipherboard_home_keystore_tee
            KeystoreSecurityLevel.SOFTWARE -> R.string.cipherboard_home_keystore_software
            KeystoreSecurityLevel.UNKNOWN -> R.string.cipherboard_home_keystore_unknown
        },
    )

    private fun OwnerIdentitySummary.toUiModel(): OwnerUiModel {
        val bytes = identityFingerprint()
        return try {
            OwnerUiModel(localOwnerName, formatFingerprint(bytes))
        } finally {
            bytes.fill(0)
        }
    }

    private fun SecureContactSummary.toUiModel(): ContactUiModel {
        val id = internalId()
        return try {
            ContactUiModel(
                navigationToken = ContactDetailsNavigation.issue(id),
                name = localName,
                status = when {
                    keyChanged || verificationStatus == ContactVerificationStatus.KEY_CHANGED ->
                        ContactStatus.KEY_CHANGED
                    sessionError || verificationStatus == ContactVerificationStatus.SESSION_ERROR ->
                        ContactStatus.SESSION_ERROR
                    requiresRepairing || verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED ->
                        ContactStatus.PAIRING_REQUIRED
                    verificationStatus == ContactVerificationStatus.VERIFIED -> ContactStatus.VERIFIED
                    else -> ContactStatus.UNVERIFIED
                },
            )
        } finally {
            id.fill(0)
        }
    }

    private fun releaseContactTokens(state: HomeScreenState) {
        (state as? HomeScreenState.Ready)?.contacts?.forEach {
            ContactDetailsNavigation.release(it.navigationToken)
        }
    }

    companion object {
        private const val PAIRING_ACTIVITY_CLASS = "helium314.keyboard.secure.pairing.PairingActivity"
        private const val HEX = "0123456789ABCDEF"

        private fun formatFingerprint(bytes: ByteArray): String {
            val compact = StringBuilder(bytes.size * 2)
            bytes.forEach { value ->
                val unsigned = value.toInt() and 0xff
                compact.append(HEX[unsigned ushr 4])
                compact.append(HEX[unsigned and 0x0f])
            }
            return compact.chunked(8).joinToString(" ")
        }
    }
}

private sealed interface HomeScreenState {
    data object Loading : HomeScreenState
    data class Locked(
        val message: String? = null,
        val isCritical: Boolean = false,
        val canResetInvalidatedVault: Boolean = false,
    ) : HomeScreenState
    data class IdentityRequired(val error: String? = null) : HomeScreenState
    data class Ready(
        val owner: OwnerUiModel,
        val contacts: List<ContactUiModel>,
        val securityLevel: String?,
    ) : HomeScreenState
}

private data class OwnerUiModel(val name: String, val fingerprint: String)
private data class ContactUiModel(
    val navigationToken: String,
    val name: String,
    val status: ContactStatus,
)
private enum class ContactStatus { VERIFIED, UNVERIFIED, KEY_CHANGED, PAIRING_REQUIRED, SESSION_ERROR }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(
    state: HomeScreenState,
    onUnlock: () -> Unit,
    onCreateIdentity: (String) -> Unit,
    onAddContact: () -> Unit,
    onOpenContact: (ContactUiModel) -> Unit,
    onKeyboardSettings: () -> Unit,
    onVaultSettings: () -> Unit,
    onLockVault: () -> Unit,
    onSecurity: () -> Unit,
    onLicenses: () -> Unit,
    showInvalidatedResetConfirmation: Boolean,
    onRequestInvalidatedReset: () -> Unit,
    onDismissInvalidatedReset: () -> Unit,
    onConfirmInvalidatedReset: () -> Unit,
) {
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cipherboard_home_title)) },
                windowInsets = WindowInsets(0),
            )
        },
    ) { padding ->
        when (state) {
            HomeScreenState.Loading -> Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
            is HomeScreenState.Locked -> LockedContent(
                state,
                padding,
                onUnlock,
                onSecurity,
                onLicenses,
                onRequestInvalidatedReset,
            )
            is HomeScreenState.IdentityRequired -> IdentityContent(
                state,
                padding,
                onCreateIdentity,
                onLockVault,
                onLicenses,
            )
            is HomeScreenState.Ready -> ReadyContent(
                state,
                padding,
                onAddContact,
                onOpenContact,
                onKeyboardSettings,
                onVaultSettings,
                onLockVault,
                onSecurity,
                onLicenses,
            )
        }
    }
    if (showInvalidatedResetConfirmation) {
        AlertDialog(
            onDismissRequest = onDismissInvalidatedReset,
            title = { Text(stringResource(R.string.cipherboard_home_reset_title)) },
            text = { Text(stringResource(R.string.cipherboard_home_reset_warning)) },
            confirmButton = {
                Button(
                    onClick = onConfirmInvalidatedReset,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) {
                    Text(stringResource(R.string.cipherboard_home_reset_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissInvalidatedReset) {
                    Text(stringResource(android.R.string.cancel))
                }
            },
        )
    }
}

@Composable
private fun LockedContent(
    state: HomeScreenState.Locked,
    padding: PaddingValues,
    onUnlock: () -> Unit,
    onSecurity: () -> Unit,
    onLicenses: () -> Unit,
    onResetInvalidatedVault: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.cipherboard_home_vault_locked), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.cipherboard_home_vault_locked_description),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        state.message?.let {
            Spacer(Modifier.height(16.dp))
            Text(
                it,
                color = if (state.isCritical) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
        }
        Spacer(Modifier.height(24.dp))
        Button(onClick = onUnlock, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.secure_unlock_vault))
        }
        if (state.canResetInvalidatedVault) {
            OutlinedButton(
                onClick = onResetInvalidatedVault,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) {
                Text(stringResource(R.string.cipherboard_home_reset_action))
            }
        }
        TextButton(onClick = onSecurity) {
            Text(stringResource(R.string.cipherboard_home_security))
        }
        TextButton(onClick = onLicenses) {
            Text(stringResource(R.string.cipherboard_home_licenses))
        }
    }
}

@Composable
private fun IdentityContent(
    state: HomeScreenState.IdentityRequired,
    padding: PaddingValues,
    onCreateIdentity: (String) -> Unit,
    onLockVault: () -> Unit,
    onLicenses: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            Text(stringResource(R.string.cipherboard_home_create_identity), style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(R.string.cipherboard_home_create_identity_description),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        item {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.cipherboard_home_local_name)) },
                supportingText = {
                    Text(state.error ?: stringResource(R.string.cipherboard_home_local_name_private))
                },
                isError = state.error != null,
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Words,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done,
                ),
            )
        }
        item {
            Button(
                onClick = { onCreateIdentity(name) },
                enabled = name.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.cipherboard_home_create))
            }
            TextButton(onClick = onLockVault, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.cipherboard_home_lock_vault))
            }
            TextButton(onClick = onLicenses, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.cipherboard_home_licenses))
            }
        }
    }
}

@Composable
private fun ReadyContent(
    state: HomeScreenState.Ready,
    padding: PaddingValues,
    onAddContact: () -> Unit,
    onOpenContact: (ContactUiModel) -> Unit,
    onKeyboardSettings: () -> Unit,
    onVaultSettings: () -> Unit,
    onLockVault: () -> Unit,
    onSecurity: () -> Unit,
    onLicenses: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(bottom = 24.dp),
    ) {
        item {
            Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp)) {
                Text(state.owner.name, style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.cipherboard_home_identity_local),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(14.dp))
                Text(stringResource(R.string.cipherboard_home_fingerprint), style = MaterialTheme.typography.labelLarge)
                Text(
                    state.owner.fingerprint,
                    modifier = Modifier.padding(top = 4.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    state.securityLevel?.let {
                        stringResource(R.string.cipherboard_home_vault_unlocked_level, it)
                    } ?: stringResource(R.string.cipherboard_home_vault_unlocked),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
            HorizontalDivider()
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp, top = 14.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.cipherboard_home_contacts),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                )
                TextButton(onClick = onAddContact) {
                    Text(stringResource(R.string.cipherboard_home_add_contact))
                }
            }
        }
        if (state.contacts.isEmpty()) {
            item {
                Text(
                    stringResource(R.string.cipherboard_home_no_contacts),
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(state.contacts, key = { it.navigationToken }) { contact ->
                ContactRow(contact) { onOpenContact(contact) }
                HorizontalDivider(modifier = Modifier.padding(start = 20.dp))
            }
        }
        item {
            Spacer(Modifier.height(18.dp))
            Column(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedButton(onClick = onKeyboardSettings, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.cipherboard_home_keyboard_settings))
                }
                OutlinedButton(onClick = onVaultSettings, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.cipherboard_vault_settings_title))
                }
                OutlinedButton(onClick = onSecurity, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.cipherboard_home_security))
                }
                OutlinedButton(onClick = onLicenses, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.cipherboard_home_licenses))
                }
                OutlinedButton(
                    onClick = onLockVault,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) {
                    Text(stringResource(R.string.cipherboard_home_lock_vault))
                }
            }
        }
    }
}

@Composable
private fun ContactRow(contact: ContactUiModel, onClick: () -> Unit) {
    val (label, color) = when (contact.status) {
        ContactStatus.VERIFIED -> R.string.cipherboard_home_status_verified to MaterialTheme.colorScheme.primary
        ContactStatus.UNVERIFIED -> R.string.cipherboard_home_status_unverified to MaterialTheme.colorScheme.onSurfaceVariant
        ContactStatus.KEY_CHANGED -> R.string.cipherboard_home_status_key_changed to MaterialTheme.colorScheme.error
        ContactStatus.PAIRING_REQUIRED -> R.string.cipherboard_home_status_pairing_required to MaterialTheme.colorScheme.error
        ContactStatus.SESSION_ERROR -> R.string.cipherboard_home_status_session_error to MaterialTheme.colorScheme.error
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(contact.name, style = MaterialTheme.typography.bodyLarge)
        Text(stringResource(label), color = color, style = MaterialTheme.typography.bodySmall)
    }
}
