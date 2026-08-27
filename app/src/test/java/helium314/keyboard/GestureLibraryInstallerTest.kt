// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard

import helium314.keyboard.latin.utils.GestureLibraryInstaller
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class GestureLibraryInstallerTest {
    @Test
    fun arm64LibraryIsPinnedToPublishedCompatibleHash() {
        assertEquals(
            "b1049983e6ac5cfc6d1c66e38959751044fad213dff0637a6cf1d2a2703e754f",
            GestureLibraryInstaller.expectedChecksum("arm64-v8a"),
        )
        assertEquals(
            "442a2a8bfcb25489564bc9433a916fa4dc0dba9000fe6f6f03f5939b985091e6",
            GestureLibraryInstaller.expectedChecksum("armeabi-v7a"),
        )
        assertEquals(
            "bd946d126c957b5a6dea3bafa07fa36a27950b30e2b684dffc60746d0a1c7ad8",
            GestureLibraryInstaller.expectedChecksum("x86_64"),
        )
        assertEquals(
            "c882e12e6d48dd946e0b644c66868a720bd11ac3fecf152000e21a3d5abd59c9",
            GestureLibraryInstaller.expectedChecksum("x86"),
        )
        assertNull(GestureLibraryInstaller.expectedChecksum("unsupported"))
    }

    @Test
    fun unknownFileIsRejectedWithoutChangingInstalledLibrary() {
        val root = Files.createTempDirectory("gesture-library-test").toFile()
        val source = root.resolve("unknown.so").apply { writeText("not a native library") }
        val destination = root.resolve("destination").apply { mkdirs() }

        assertEquals(
            GestureLibraryInstaller.InstallResult.CHECKSUM_MISMATCH,
            GestureLibraryInstaller.install(source, destination, "arm64-v8a"),
        )
        assertFalse(GestureLibraryInstaller.installedLibrary(destination).exists())

        root.deleteRecursively()
    }
}
