// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin.utils

import android.os.Build
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** Installs only known, ABI-specific gesture libraries into app-private storage. */
object GestureLibraryInstaller {
    const val IMPORT_FILE_NAME = "libjni_latinime.so"
    const val MAX_LIBRARY_BYTES = 8L * 1024L * 1024L

    private val trustedChecksums = mapOf(
        "arm64-v8a" to "b1049983e6ac5cfc6d1c66e38959751044fad213dff0637a6cf1d2a2703e754f",
        "armeabi-v7a" to "442a2a8bfcb25489564bc9433a916fa4dc0dba9000fe6f6f03f5939b985091e6",
        "x86_64" to "bd946d126c957b5a6dea3bafa07fa36a27950b30e2b684dffc60746d0a1c7ad8",
        "x86" to "c882e12e6d48dd946e0b644c66868a720bd11ac3fecf152000e21a3d5abd59c9",
    )

    enum class InstallResult {
        INSTALLED,
        UNSUPPORTED_ABI,
        FILE_TOO_LARGE,
        CHECKSUM_MISMATCH,
        IO_ERROR,
    }

    fun primaryAbi(): String = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()

    fun expectedChecksum(abi: String = primaryAbi()): String? = trustedChecksums[abi]

    fun installedLibrary(filesDir: File): File = File(filesDir, IMPORT_FILE_NAME)

    fun validInstalledLibrary(filesDir: File, abi: String = primaryAbi()): File? {
        val library = installedLibrary(filesDir)
        val expected = expectedChecksum(abi) ?: return null
        if (!library.isFile || library.length() !in 1..MAX_LIBRARY_BYTES) return null
        return library.takeIf { ChecksumCalculator.checksum(it) == expected }
    }

    fun install(source: File, filesDir: File, abi: String = primaryAbi()): InstallResult {
        val expected = expectedChecksum(abi) ?: return InstallResult.UNSUPPORTED_ABI
        if (!source.isFile) return InstallResult.IO_ERROR
        if (source.length() !in 1..MAX_LIBRARY_BYTES) return InstallResult.FILE_TOO_LARGE
        if (ChecksumCalculator.checksum(source) != expected) return InstallResult.CHECKSUM_MISMATCH

        val destination = installedLibrary(filesDir)
        val candidate = File(filesDir, "$IMPORT_FILE_NAME.new")
        return try {
            if (!filesDir.exists() && !filesDir.mkdirs()) throw IOException("files directory unavailable")
            deleteWritable(candidate)

            // Android 14 requires dynamically loaded code to be read-only before its bytes are
            // written. The already-open descriptor remains writable while the path is read-only.
            FileOutputStream(candidate).use { output ->
                if (!candidate.setReadOnly()) throw IOException("could not protect candidate")
                source.inputStream().use { input -> input.copyTo(output) }
                output.fd.sync()
            }
            if (ChecksumCalculator.checksum(candidate) != expected) {
                deleteWritable(candidate)
                return InstallResult.CHECKSUM_MISMATCH
            }

            deleteWritable(destination)
            if (!candidate.renameTo(destination)) throw IOException("could not commit gesture library")
            InstallResult.INSTALLED
        } catch (_: IOException) {
            deleteWritable(candidate)
            InstallResult.IO_ERROR
        }
    }

    fun delete(filesDir: File): Boolean = deleteWritable(installedLibrary(filesDir))

    private fun deleteWritable(file: File): Boolean {
        if (!file.exists()) return true
        file.setWritable(true, true)
        return file.delete()
    }
}
