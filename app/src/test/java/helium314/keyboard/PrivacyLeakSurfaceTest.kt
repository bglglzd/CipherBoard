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

    private fun mainSourceRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
        return sequenceOf(
            workingDirectory.resolve("src/main/java"),
            workingDirectory.resolve("app/src/main/java"),
        ).first { it.exists() }
    }
}
