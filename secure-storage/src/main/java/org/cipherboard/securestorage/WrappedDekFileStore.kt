package org.cipherboard.securestorage

import android.content.Context
import android.os.Build
import android.util.AtomicFile
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.IOException

internal data class WrappedDekEnvelope(
    val alias: String,
    val authenticationMode: VaultAuthenticationMode,
    val protectionInfo: KeyProtectionInfo,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
)

internal class WrappedDekFileStore(context: Context) {
    private val credentialContext = context.requireCredentialProtectedStorage()
    private val directory = File(credentialContext.noBackupFilesDir, DIRECTORY)
    private val atomicFile = AtomicFile(File(directory, FILE_NAME))

    @Throws(VaultCorruptException::class)
    fun read(): WrappedDekEnvelope? {
        if (!atomicFile.baseFile.exists()) return null
        try {
            DataInputStream(BufferedInputStream(atomicFile.openRead())).use { input ->
                if (input.readInt() != MAGIC) throw VaultCorruptException("Invalid wrapped DEK header")
                if (input.readInt() != FORMAT_VERSION) throw VaultCorruptException("Unsupported wrapped DEK version")
                val alias = input.readUTF()
                if (alias.isBlank() || alias.length > MAX_ALIAS_CHARS) {
                    throw VaultCorruptException("Invalid wrapped DEK alias")
                }
                val mode = enumValue<VaultAuthenticationMode>(input.readInt(), "authentication mode")
                val level = enumValue<KeystoreSecurityLevel>(input.readInt(), "security level")
                val attempted = input.readBoolean()
                val succeeded = input.readBoolean()
                val nonce = readBoundedBytes(input, MIN_NONCE_BYTES, MAX_NONCE_BYTES, "nonce")
                val ciphertext = readBoundedBytes(input, MIN_WRAPPED_BYTES, MAX_WRAPPED_BYTES, "ciphertext")
                if (input.read() != -1) throw VaultCorruptException("Trailing wrapped DEK data")
                return WrappedDekEnvelope(
                    alias,
                    mode,
                    KeyProtectionInfo(level, attempted, succeeded, mode),
                    nonce,
                    ciphertext,
                )
            }
        } catch (e: VaultCorruptException) {
            throw e
        } catch (e: EOFException) {
            throw VaultCorruptException("Truncated wrapped DEK", e)
        } catch (e: IOException) {
            throw VaultCorruptException("Cannot read wrapped DEK", e)
        }
    }

    @Throws(VaultStorageException::class)
    fun write(envelope: WrappedDekEnvelope) {
        require(envelope.alias.isNotBlank() && envelope.alias.length <= MAX_ALIAS_CHARS)
        require(envelope.nonce.size in MIN_NONCE_BYTES..MAX_NONCE_BYTES)
        require(envelope.ciphertext.size in MIN_WRAPPED_BYTES..MAX_WRAPPED_BYTES)
        directory.mkdirs()
        val output = try {
            atomicFile.startWrite()
        } catch (e: IOException) {
            throw VaultStorageException("Cannot start wrapped DEK write", e)
        }
        try {
            val data = DataOutputStream(BufferedOutputStream(output))
            data.writeInt(MAGIC)
            data.writeInt(FORMAT_VERSION)
            data.writeUTF(envelope.alias)
            data.writeInt(envelope.authenticationMode.ordinal)
            data.writeInt(envelope.protectionInfo.securityLevel.ordinal)
            data.writeBoolean(envelope.protectionInfo.strongBoxAttempted)
            data.writeBoolean(envelope.protectionInfo.strongBoxGenerationSucceeded)
            data.writeInt(envelope.nonce.size)
            data.write(envelope.nonce)
            data.writeInt(envelope.ciphertext.size)
            data.write(envelope.ciphertext)
            data.flush()
            atomicFile.finishWrite(output)
        } catch (e: Exception) {
            atomicFile.failWrite(output)
            throw VaultStorageException("Cannot commit wrapped DEK", e)
        }
    }

    fun delete() {
        atomicFile.delete()
    }

    private fun readBoundedBytes(
        input: DataInputStream,
        min: Int,
        max: Int,
        label: String,
    ): ByteArray {
        val size = input.readInt()
        if (size !in min..max) throw VaultCorruptException("Invalid wrapped DEK $label length")
        return ByteArray(size).also(input::readFully)
    }

    private inline fun <reified T : Enum<T>> enumValue(ordinal: Int, label: String): T {
        return enumValues<T>().getOrNull(ordinal)
            ?: throw VaultCorruptException("Invalid wrapped DEK $label")
    }

    companion object {
        private const val DIRECTORY = "cipherboard_vault"
        private const val FILE_NAME = "wrapped_dek.bin"
        private const val MAGIC = 0x4342564b // CBVK
        private const val FORMAT_VERSION = 2
        private const val MAX_ALIAS_CHARS = 128
        private const val MIN_NONCE_BYTES = 12
        private const val MAX_NONCE_BYTES = 32
        private const val MIN_WRAPPED_BYTES = RecordCrypto.DEK_BYTES + RecordCrypto.TAG_BYTES
        private const val MAX_WRAPPED_BYTES = 256
    }
}

internal fun Context.requireCredentialProtectedStorage(): Context {
    if (Build.VERSION.SDK_INT >= 24 && isDeviceProtectedStorage) {
        throw IllegalArgumentException("Vault requires a credential-protected Context")
    }
    return this
}
