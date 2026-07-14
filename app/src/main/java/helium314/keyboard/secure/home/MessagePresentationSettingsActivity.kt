// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import helium314.keyboard.latin.R
import helium314.keyboard.latin.utils.BackButton
import helium314.keyboard.latin.utils.Theme
import org.cipherboard.cryptocore.TransportPresentation
import org.cipherboard.securekeyboard.runtime.MessagePresentationPreferences

/** Selects the non-secret text representation used for future outgoing ciphertext. */
class MessagePresentationSettingsActivity : FragmentActivity() {
    private val selectedPresentation = mutableStateOf(TransportPresentation.COMPACT)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        selectedPresentation.value = MessagePresentationPreferences.read(this)
        setContent {
            Theme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    MessagePresentationSettingsScreen(
                        selected = selectedPresentation.value,
                        onSelected = ::selectPresentation,
                        onBack = onBackPressedDispatcher::onBackPressed,
                    )
                }
            }
        }
    }

    private fun selectPresentation(presentation: TransportPresentation) {
        if (MessagePresentationPreferences.write(this, presentation)) {
            selectedPresentation.value = presentation
        } else {
            Toast.makeText(this, R.string.cipherboard_message_format_save_failed, Toast.LENGTH_SHORT).show()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MessagePresentationSettingsScreen(
    selected: TransportPresentation,
    onSelected: (TransportPresentation) -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cipherboard_message_format_title)) },
                navigationIcon = { BackButton(onBack) },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).selectableGroup(),
            contentPadding = PaddingValues(bottom = 32.dp),
        ) {
            item {
                Text(
                    stringResource(R.string.cipherboard_message_format_description),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
            items(MESSAGE_PRESENTATION_OPTIONS.size) { index ->
                val option = MESSAGE_PRESENTATION_OPTIONS[index]
                MessagePresentationOption(
                    option = option,
                    selected = selected == option.presentation,
                    onSelected = { onSelected(option.presentation) },
                )
                if (index < MESSAGE_PRESENTATION_OPTIONS.lastIndex) HorizontalDivider()
            }
            item {
                HorizontalDivider()
                Text(
                    stringResource(R.string.cipherboard_message_format_warning),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 18.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
    }
}

@Composable
private fun MessagePresentationOption(
    option: MessagePresentationOption,
    selected: Boolean,
    onSelected: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(
                selected = selected,
                onClick = onSelected,
                role = Role.RadioButton,
            )
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Column(modifier = Modifier.weight(1f).padding(start = 12.dp)) {
            Text(stringResource(option.title), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(3.dp))
            Text(
                stringResource(option.description),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

private data class MessagePresentationOption(
    val presentation: TransportPresentation,
    val title: Int,
    val description: Int,
)

private val MESSAGE_PRESENTATION_OPTIONS = listOf(
    MessagePresentationOption(
        TransportPresentation.COMPACT,
        R.string.cipherboard_message_format_compact,
        R.string.cipherboard_message_format_compact_description,
    ),
    MessagePresentationOption(
        TransportPresentation.RUSSIAN_WORDS,
        R.string.cipherboard_message_format_russian,
        R.string.cipherboard_message_format_russian_description,
    ),
    MessagePresentationOption(
        TransportPresentation.ENGLISH_WORDS,
        R.string.cipherboard_message_format_english,
        R.string.cipherboard_message_format_english_description,
    ),
)
