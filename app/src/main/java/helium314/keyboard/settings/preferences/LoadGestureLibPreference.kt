// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.settings.preferences

import android.content.Intent
import androidx.annotation.StringRes
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import helium314.keyboard.latin.R
import helium314.keyboard.latin.common.FileUtils
import helium314.keyboard.latin.utils.GestureLibraryInstaller
import helium314.keyboard.settings.Setting
import helium314.keyboard.settings.dialogs.ConfirmationDialog
import helium314.keyboard.settings.dialogs.InfoDialog
import helium314.keyboard.settings.filePicker
import java.io.File
import java.io.IOException
import kotlin.system.exitProcess

@Composable
fun LoadGestureLibPreference(setting: Setting) {
    val context = LocalContext.current
    val installedFile = GestureLibraryInstaller.installedLibrary(context.filesDir)
    val isInstalled = GestureLibraryInstaller.validInstalledLibrary(context.filesDir) != null
    var showDialog by rememberSaveable { mutableStateOf(false) }
    @StringRes var errorMessage by rememberSaveable { mutableStateOf<Int?>(null) }

    fun restartProcess() {
        // The AOSP and gesture implementations export the same JNI entry points, so the verified
        // library must be selected at the next process start, before the fallback is loaded.
        exitProcess(0)
    }

    val launcher = filePicker { uri ->
        val stagingFile = File(context.cacheDir, "gesture-library-import")
        val result = try {
            stagingFile.delete()
            FileUtils.copyContentUriToNewFile(uri, context, stagingFile)
            GestureLibraryInstaller.install(stagingFile, context.filesDir)
        } catch (_: IOException) {
            GestureLibraryInstaller.InstallResult.IO_ERROR
        } catch (_: SecurityException) {
            GestureLibraryInstaller.InstallResult.IO_ERROR
        } finally {
            stagingFile.delete()
        }

        errorMessage = when (result) {
            GestureLibraryInstaller.InstallResult.INSTALLED -> {
                restartProcess()
                null
            }
            GestureLibraryInstaller.InstallResult.UNSUPPORTED_ABI -> R.string.gesture_library_unsupported_abi
            GestureLibraryInstaller.InstallResult.FILE_TOO_LARGE -> R.string.gesture_library_file_too_large
            GestureLibraryInstaller.InstallResult.CHECKSUM_MISMATCH -> R.string.checksum_mismatch_message
            GestureLibraryInstaller.InstallResult.IO_ERROR -> R.string.gesture_library_import_error
        }
    }

    Preference(
        name = setting.title,
        description = stringResource(
            if (isInstalled) R.string.gesture_library_installed else R.string.load_gesture_library_summary
        ),
        onClick = { showDialog = true },
    )

    if (showDialog) {
        ConfirmationDialog(
            onDismissRequest = { showDialog = false },
            onConfirmed = {
                showDialog = false
                launcher.launch(
                    Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("*/*")
                )
            },
            confirmButtonText = stringResource(R.string.load_gesture_library_button_load),
            title = { Text(stringResource(R.string.load_gesture_library)) },
            content = {
                Text(
                    stringResource(
                        R.string.load_gesture_library_message,
                        GestureLibraryInstaller.primaryAbi(),
                    )
                )
            },
            neutralButtonText = if (installedFile.exists()) {
                stringResource(R.string.load_gesture_library_button_delete)
            } else {
                null
            },
            onNeutral = {
                showDialog = false
                if (GestureLibraryInstaller.delete(context.filesDir)) {
                    restartProcess()
                } else {
                    errorMessage = R.string.gesture_library_delete_error
                }
            },
        )
    }

    errorMessage?.let { message ->
        InfoDialog(stringResource(message)) { errorMessage = null }
    }
}
