// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.os.Bundle
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
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import helium314.keyboard.latin.utils.BackButton
import helium314.keyboard.latin.utils.Theme

/** Plain-language statement of CipherBoard's protection boundary and residual risks. */
class SecurityInfoActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Theme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    SecurityInfoScreen(onBack = onBackPressedDispatcher::onBackPressed)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SecurityInfoScreen(onBack: () -> Unit) {
    val protections = listOf(
        R.string.cipherboard_security_protect_transport,
        R.string.cipherboard_security_protect_integrity,
        R.string.cipherboard_security_protect_storage,
        R.string.cipherboard_security_protect_plaintext,
        R.string.cipherboard_security_protect_offline,
    )
    val limitations = listOf(
        R.string.cipherboard_security_limit_unlocked_device,
        R.string.cipherboard_security_limit_os,
        R.string.cipherboard_security_limit_apk,
        R.string.cipherboard_security_limit_observation,
        R.string.cipherboard_security_limit_accessibility,
        R.string.cipherboard_security_limit_metadata,
        R.string.cipherboard_security_limit_coercion,
        R.string.cipherboard_security_limit_defects,
    )

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cipherboard_security_title)) },
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
                        stringResource(R.string.cipherboard_security_intro),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        stringResource(R.string.cipherboard_security_pairing_warning),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                HorizontalDivider()
                SectionTitle(R.string.cipherboard_security_protects_title)
            }
            items(protections) { BulletText(it) }
            item {
                Spacer(Modifier.height(12.dp))
                HorizontalDivider()
                SectionTitle(R.string.cipherboard_security_limits_title)
            }
            items(limitations) { BulletText(it) }
            item {
                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 18.dp)) {
                    Text(
                        stringResource(R.string.cipherboard_security_audit_notice),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        stringResource(R.string.cipherboard_security_high_risk),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(text: Int) {
    Text(
        stringResource(text),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
        style = MaterialTheme.typography.titleMedium,
    )
}

@Composable
private fun BulletText(text: Int) {
    Text(
        text = "\u2022 ${stringResource(text)}",
        modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 6.dp),
        style = MaterialTheme.typography.bodyLarge,
    )
}
