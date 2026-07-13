// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.app.Activity
import androidx.fragment.app.FragmentActivity
import java.io.Closeable

/**
 * Narrow bridge between the exported text action and the application crypto/storage runtime.
 *
 * Implementations must atomically persist the advanced inbound ratchet and an encrypted pending
 * display record before returning [DecryptResult.Success]. A callback may be delivered on any
 * thread. Neither parsed handles nor result objects may include secrets in `toString()` output.
 */
interface SecureDecryptBackend {
    fun parse(parts: List<String>): ParseResult

    fun decrypt(
        host: FragmentActivity,
        parsed: ParsedCiphertext,
        callback: (DecryptResult) -> Unit,
    ): DecryptOperation

    /** Starts Secure Composer for the contact represented by [token]. */
    fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean

    /** Viewer timeout, clamped by the activity to its supported security range. */
    val viewerTimeoutMillis: Long
        get() = DEFAULT_VIEWER_TIMEOUT_MILLIS
}

/** Host bridge for API 23-29, where DEVICE_CREDENTIAL needs Keyguard confirmation UI. */
interface LegacyDeviceCredentialHost {
    /** Returns false when the platform cannot present credential confirmation. */
    fun requestLegacyDeviceCredential(callback: (Boolean) -> Unit): Boolean
}

/** Opaque, backend-owned parse result. Closing it must wipe any routing metadata it owns. */
interface ParsedCiphertext : Closeable

/** Opaque, backend-owned contact capability used only to start a secure reply. */
interface SecureReplyToken : Closeable

/**
 * Owns the encrypted pending-display record while plaintext is being handed to the viewer.
 *
 * Closing before [markDisplayed] must retain the encrypted record so an interrupted Activity can
 * recover it. Once the viewer has rendered the plaintext, closing deletes the record.
 */
interface SecureDisplayLease : Closeable {
    fun markDisplayed()
}

fun interface DecryptOperation {
    fun cancel()
}

enum class ParseFailureReason {
    INVALID_FORMAT,
    UNSUPPORTED_VERSION,
    MISSING_PART,
    INCONSISTENT_PARTS,
    TOO_MANY_PARTS,
    WRONG_CONTACT,
    INTERNAL_ERROR,
}

sealed interface ParseResult {
    class Success(val parsed: ParsedCiphertext) : ParseResult {
        override fun toString(): String = "ParseResult.Success(redacted)"
    }

    data class Failure(val reason: ParseFailureReason) : ParseResult
}

enum class DecryptFailureReason {
    VAULT_LOCKED,
    AUTHENTICATION_CANCELLED,
    WRONG_CONTACT,
    REPLAY,
    MISSING_PART,
    INVALID_CIPHERTEXT,
    SESSION_ERROR,
    KEY_CHANGED,
    INTERNAL_ERROR,
}

sealed interface DecryptResult {
    class Success(val message: DecryptedMessage) : DecryptResult {
        override fun toString(): String = "DecryptResult.Success(redacted)"
    }

    data class Failure(val reason: DecryptFailureReason) : DecryptResult
}

enum class DecryptedContactStatus {
    VERIFIED,
    UNVERIFIED,
}

/**
 * Owns the decrypted message bytes. [close] is idempotent and wipes the backing array.
 *
 * The factory takes ownership: callers must not read or modify [bytes] after passing it here.
 */
class WipeablePlaintext private constructor(bytes: ByteArray) : Closeable {
    private var value: ByteArray? = bytes

    val size: Int
        @Synchronized get() = value?.size ?: 0

    @Synchronized
    fun <T> withBytes(block: (ByteArray) -> T): T {
        val current = value ?: throw IllegalStateException("Plaintext is closed")
        return block(current)
    }

    @Synchronized
    override fun close() {
        value?.fill(0)
        value = null
    }

    override fun toString(): String = "WipeablePlaintext(redacted)"

    companion object {
        fun takeOwnership(bytes: ByteArray): WipeablePlaintext = WipeablePlaintext(bytes)
    }
}

/** A one-shot viewer result. Contact labels are local display data and must never be logged. */
class DecryptedMessage(
    val plaintext: WipeablePlaintext,
    val localContactLabel: String,
    val contactStatus: DecryptedContactStatus,
    val replyToken: SecureReplyToken?,
    private val displayLease: SecureDisplayLease,
) : Closeable {
    private var closed = false

    @Synchronized
    fun markDisplayed() {
        check(!closed) { "Decrypted message is closed" }
        displayLease.markDisplayed()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        plaintext.close()
        runCatching { replyToken?.close() }
        runCatching { displayLease.close() }
    }

    override fun toString(): String = "DecryptedMessage(redacted)"
}

/** Process-wide installation point. The application installs exactly one backend during startup. */
object SecureDecryptRuntime {
    @Volatile
    private var backend: SecureDecryptBackend? = null

    @Synchronized
    fun install(value: SecureDecryptBackend) {
        val current = backend
        require(current == null || current === value) { "Secure decrypt backend is already installed" }
        backend = value
    }

    fun parse(parts: List<String>): ParseResult {
        val current = backend ?: return ParseResult.Failure(ParseFailureReason.INTERNAL_ERROR)
        return try {
            current.parse(parts)
        } catch (_: Throwable) {
            ParseResult.Failure(ParseFailureReason.INTERNAL_ERROR)
        }
    }

    fun decrypt(
        host: FragmentActivity,
        parsed: ParsedCiphertext,
        callback: (DecryptResult) -> Unit,
    ): DecryptOperation {
        val current = backend
            ?: return DecryptOperation { }.also {
                callback(DecryptResult.Failure(DecryptFailureReason.INTERNAL_ERROR))
            }
        return try {
            current.decrypt(host, parsed, callback)
        } catch (_: Throwable) {
            callback(DecryptResult.Failure(DecryptFailureReason.INTERNAL_ERROR))
            DecryptOperation { }
        }
    }

    fun openSecureReply(host: Activity, token: SecureReplyToken): Boolean {
        val current = backend ?: return false
        return try {
            current.openSecureReply(host, token)
        } catch (_: Throwable) {
            false
        }
    }

    fun viewerTimeoutMillis(): Long = backend?.viewerTimeoutMillis ?: DEFAULT_VIEWER_TIMEOUT_MILLIS
}

internal const val DEFAULT_VIEWER_TIMEOUT_MILLIS = 60_000L
