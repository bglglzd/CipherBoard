// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard

import helium314.keyboard.latin.utils.Log
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class PrivacyLeakSurfaceTest {
    @Test
    fun compatibilityLoggerEmitsNoPayload() {
        val tag = "CipherBoardPrivacyTest"
        val sentinel = "plaintext-must-not-be-logged"
        ShadowLog.clear()

        Log.wtf(tag, sentinel)
        Log.e(tag, sentinel, IllegalStateException(sentinel))
        Log.w(tag, sentinel)
        Log.i(tag, sentinel)
        Log.d(tag, sentinel)
        Log.v(tag, sentinel)

        assertTrue(ShadowLog.getLogsForTag(tag).isEmpty())
    }

    @Test
    fun sourcesContainNoCrashOrLogcatExportSurface() {
        val forbidden = listOf(
            "CrashReportExceptionHandler",
            "crash_report",
            "logcat -d",
            "Log.getLog(",
            "setDefaultUncaughtExceptionHandler(",
            "android.util.Log",
            "READ_CONTACTS",
            "PREF_USE_CONTACTS",
            "use_contacts_dict",
            "BackupRestorePreference",
            "ContextCompat.RECEIVER_EXPORTED",
        )
        val violations = Files.walk(mainSourceRoot()).use { paths ->
            paths.filter {
                Files.isRegularFile(it) &&
                    (it.fileName.toString().endsWith(".kt") || it.fileName.toString().endsWith(".java"))
            }
                .flatMap { path ->
                    val source = String(Files.readAllBytes(path), StandardCharsets.UTF_8)
                    forbidden.filter(source::contains).map { "${path.fileName}: $it" }.stream()
                }
                .toList()
        }

        assertFalse(violations.isNotEmpty(), violations.joinToString())
    }

    @Test
    fun gestureLibraryImportHasNoUnverifiedOverride() {
        val utilsRoot = mainSourceRoot().resolve("helium314/keyboard/latin/utils")
        val installer = sourceText(utilsRoot.resolve("GestureLibraryInstaller.kt"))
        val jniUtils = sourceText(utilsRoot.resolve("JniUtils.java"))
        val preference = sourceText(
            mainSourceRoot().resolve("helium314/keyboard/settings/preferences/LoadGestureLibPreference.kt")
        )

        assertTrue(installer.contains("trustedChecksums"))
        assertTrue(installer.contains("ChecksumCalculator.checksum(source) != expected"))
        assertTrue(installer.contains("ChecksumCalculator.checksum(candidate) != expected"))
        assertTrue(jniUtils.contains("validInstalledLibrary"))
        assertTrue(jniUtils.contains("System.load(importedLibrary.getAbsolutePath())"))
        assertFalse(preference.contains("PREF_LIBRARY_CHECKSUM"))
        assertFalse(preference.contains("Are you sure"))
    }

    @Test
    fun launcherBroadcastReceiverDoesNotKillOnLocaleOrBootBroadcast() {
        val receiver = mainSourceRoot().resolve("helium314/keyboard/latin/SystemBroadcastReceiver.java")
        val source = String(Files.readAllBytes(receiver), StandardCharsets.UTF_8)

        assertFalse(source.contains("killProcess"))
        assertFalse(source.contains("System.exit"))
    }

    private fun mainSourceRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
        return sequenceOf(
            workingDirectory.resolve("src/main/java"),
            workingDirectory.resolve("app/src/main/java"),
        ).first { it.exists() }
    }

    private fun sourceText(path: Path) =
        String(Files.readAllBytes(path), StandardCharsets.UTF_8)
}
