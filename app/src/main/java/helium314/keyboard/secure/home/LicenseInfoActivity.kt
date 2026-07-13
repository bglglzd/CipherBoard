// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import helium314.keyboard.latin.utils.BackButton
import helium314.keyboard.latin.utils.Theme

/** Offline license, corresponding-source, and upstream attribution viewer. */
class LicenseInfoActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Theme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    LicenseInfoScreen(onBack = onBackPressedDispatcher::onBackPressed)
                }
            }
        }
    }
}

private data class LicenseDocument(@StringRes val title: Int, val assetName: String)

private val licenseDocuments = listOf(
    LicenseDocument(R.string.cipherboard_licenses_gpl, "licenses/LICENSE"),
    LicenseDocument(R.string.cipherboard_licenses_inventory, "licenses/LICENSES.md"),
    LicenseDocument(R.string.cipherboard_licenses_notices, "licenses/THIRD_PARTY_NOTICES.md"),
    LicenseDocument(R.string.cipherboard_licenses_upstream, "licenses/UPSTREAM.md"),
    LicenseDocument(R.string.cipherboard_licenses_apache, "licenses/LICENSE-Apache-2.0"),
    LicenseDocument(R.string.cipherboard_licenses_blue_oak, "licenses/LICENSE-BlueOak-1.0.0"),
    LicenseDocument(R.string.cipherboard_licenses_bsd, "licenses/LICENSE-BSD-3-Clause-NOTICES"),
    LicenseDocument(R.string.cipherboard_licenses_cc, "licenses/LICENSE-CC-BY-SA-4.0"),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LicenseInfoScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var selected by remember { mutableStateOf(licenseDocuments.first()) }
    val document = remember(selected) {
        runCatching {
            context.assets.open(selected.assetName).bufferedReader(Charsets.UTF_8).use { it.readText() }
        }.getOrElse { context.getString(R.string.cipherboard_licenses_read_failed) }
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cipherboard_licenses_title)) },
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
                Text(
                    stringResource(R.string.cipherboard_licenses_source_notice),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                HorizontalDivider()
            }
            items(licenseDocuments, key = { it.assetName }) { item ->
                Column(
                    Modifier.fillMaxWidth().clickable { selected = item }.padding(horizontal = 20.dp, vertical = 12.dp),
                ) {
                    Text(
                        stringResource(item.title),
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (selected == item) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                    )
                }
            }
            item {
                HorizontalDivider()
                Spacer(Modifier.height(16.dp))
                Text(
                    stringResource(selected.title),
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    document,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}
