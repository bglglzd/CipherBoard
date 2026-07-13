// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.update

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.BuildConfig
import helium314.keyboard.latin.R
import helium314.keyboard.latin.utils.BackButton
import helium314.keyboard.latin.utils.Theme

/** Offline update guidance. Network access and APK installation remain outside CipherBoard. */
class UpdateInfoActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Theme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    UpdateInfoScreen(
                        versionName = BuildConfig.VERSION_NAME,
                        onBack = onBackPressedDispatcher::onBackPressed,
                        onOpenRepository = ::openRepository,
                    )
                }
            }
        }
    }

    private fun openRepository() {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(REPOSITORY_URL)))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, R.string.cipherboard_updates_open_failed, Toast.LENGTH_SHORT).show()
        }
    }

    private companion object {
        const val REPOSITORY_URL = "https://github.com/bglglzd/CipherBoard"
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun UpdateInfoScreen(
    versionName: String,
    onBack: () -> Unit,
    onOpenRepository: () -> Unit,
) {
    val setupSteps = listOf(
        R.string.cipherboard_updates_step_install_obtainium,
        R.string.cipherboard_updates_step_add_source,
        R.string.cipherboard_updates_step_stable_releases,
        R.string.cipherboard_updates_step_allow_installs,
    )

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cipherboard_updates_title)) },
                navigationIcon = { BackButton(onBack) },
                windowInsets = WindowInsets(0),
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(bottom = 32.dp),
        ) {
            item {
                Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp)) {
                    Text(
                        stringResource(R.string.cipherboard_updates_offline_notice),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(
                        stringResource(R.string.cipherboard_updates_current_version, versionName),
                        style = MaterialTheme.typography.titleMedium,
                    )
                }
                HorizontalDivider()
                Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp)) {
                    Text(
                        stringResource(R.string.cipherboard_updates_repository_title),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.cipherboard_updates_repository_url),
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = onOpenRepository, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.cipherboard_updates_open_repository))
                    }
                }
                HorizontalDivider()
                Text(
                    stringResource(R.string.cipherboard_updates_obtainium_title),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            itemsIndexed(setupSteps) { index, text ->
                Text(
                    text = stringResource(R.string.cipherboard_updates_numbered_step, index + 1, stringResource(text)),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 6.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
            item {
                Spacer(Modifier.height(14.dp))
                Text(
                    stringResource(R.string.cipherboard_updates_keep_data_warning),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    stringResource(R.string.cipherboard_updates_signature_notice),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
