// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.os.IBinder
import org.cipherboard.securekeyboard.runtime.OutboundCommitBoundary
import org.cipherboard.securekeyboard.runtime.PreparedOutbound
import java.util.UUID

fun interface CiphertextCommitter {
    fun commit(ciphertext: String): Boolean
}

fun interface OutboundCompletion {
    fun complete(operationId: ByteArray): Boolean
}

enum class CiphertextDeliveryResult {
    NO_HANDOFF,
    HOST_COMMIT_UNCERTAIN,
    COMMITTED_AND_COMPLETED,
    COMMITTED_PENDING_CLEANUP,
}

private class HostEditorScope(
    val packageName: String,
    val uid: Int,
    val fieldId: Int,
    val fieldName: String?,
    val inputType: Int,
    val imeOptions: Int,
    val privateImeOptions: String?,
    val initialSelectionStart: Int,
    val initialSelectionEnd: Int,
    val connectionIdentity: Any,
) {
    fun matches(other: HostEditorScope): Boolean =
        packageName == other.packageName && uid == other.uid && fieldId == other.fieldId &&
            fieldName == other.fieldName && inputType == other.inputType && imeOptions == other.imeOptions &&
            privateImeOptions == other.privateImeOptions && initialSelectionStart == other.initialSelectionStart &&
            initialSelectionEnd == other.initialSelectionEnd && connectionIdentity === other.connectionIdentity
}

private class HandoffSession(
    val token: String,
    val host: HostEditorScope,
    val expiresAtNanos: Long,
) {
    var composerActivated = false
    var operationId: ByteArray? = null
    var ciphertext: String? = null
    var commitBoundary: OutboundCommitBoundary? = null
    var activeClaim: CiphertextClaim? = null

    fun wipe() {
        operationId?.fill(0)
        operationId = null
        ciphertext = null
        activeClaim?.close()
        activeClaim = null
        commitBoundary?.close()
        commitBoundary = null
    }
}

/**
 * A process-local, one-shot gate between the secure composer and the editor that launched it.
 *
 * The composer can arm the gate only with a [PreparedOutbound] returned after the atomic ratchet
 * transaction. It cannot ask the IME to insert an arbitrary string. The IME can claim that exact
 * ciphertext only after Android restores the original editor UID/package/field scope. Android can
 * replace or temporarily omit RemoteInputConnection Binder tokens across IME transitions. The IME
 * therefore proves liveness by holding a current InputConnection before calling this gate; a
 * Binder token is not treated as a stable editor identifier.
 */
object SecureImeBridge {
    private var session: HandoffSession? = null

    /** Starts a handoff before launching the composer. Only one handoff may exist at a time. */
    @JvmStatic
    @Synchronized
    fun beginSession(
        packageName: String?,
        uid: Int,
        connectionToken: IBinder?,
        connectionIdentity: Any?,
        fieldId: Int,
        fieldName: String?,
        inputType: Int,
        imeOptions: Int,
        privateImeOptions: String?,
        initialSelectionStart: Int,
        initialSelectionEnd: Int,
        ownPackageName: String,
    ): String? {
        val host = editorScope(
            packageName,
            uid,
            connectionToken,
            connectionIdentity,
            fieldId,
            fieldName,
            inputType,
            imeOptions,
            privateImeOptions,
            initialSelectionStart,
            initialSelectionEnd,
        ) ?: return null
        if (host.packageName == ownPackageName) return null
        clearLocked()
        val token = UUID.randomUUID().toString()
        session = HandoffSession(token, host, deadlineNanos())
        return token
    }

    /** Proves that the non-exported composer received the token created by the IME. */
    @JvmStatic
    @Synchronized
    fun activateComposer(token: String): Boolean {
        val current = liveSessionLocked() ?: return false
        if (current.token != token) return false
        current.composerActivated = true
        return true
    }

    /** Arms the session with the exact durable pending operation and no plaintext. */
    @JvmStatic
    @Synchronized
    fun arm(token: String, outbound: PreparedOutbound): Boolean {
        val current = liveSessionLocked() ?: return false
        if (current.token != token || !current.composerActivated || current.operationId != null) return false
        val deliveryText = outbound.deliveryText
        if (deliveryText.length !in 1..PreparedOutbound.MAX_DELIVERY_TEXT_CHARS) return false
        val boundary = outbound.claimCommitBoundary() ?: return false
        current.operationId = outbound.operationId()
        current.ciphertext = deliveryText
        current.commitBoundary = boundary
        return true
    }

    /** Cancels an unarmed composer session. A durable outbound record is never deleted here. */
    @JvmStatic
    @Synchronized
    fun cancelSession(token: String) {
        if (session?.token == token) clearLocked()
    }

    /** Clears process-local state when the IME service is destroyed. */
    @JvmStatic
    @Synchronized
    fun clear() = clearLocked()

    /**
     * Commits only the ciphertext bound to this returning host editor. The durable pending record
     * is first moved to COMMIT_UNCERTAIN, then completed strictly after
     * InputConnection.commitText reports success.
     */
    @JvmStatic
    fun deliver(
        packageName: String?,
        uid: Int,
        connectionToken: IBinder?,
        connectionIdentity: Any?,
        fieldId: Int,
        fieldName: String?,
        inputType: Int,
        imeOptions: Int,
        privateImeOptions: String?,
        initialSelectionStart: Int,
        initialSelectionEnd: Int,
        committer: CiphertextCommitter,
        completion: OutboundCompletion,
    ): CiphertextDeliveryResult {
        val host = editorScope(
            packageName,
            uid,
            connectionToken,
            connectionIdentity,
            fieldId,
            fieldName,
            inputType,
            imeOptions,
            privateImeOptions,
            initialSelectionStart,
            initialSelectionEnd,
        )
            ?: return CiphertextDeliveryResult.NO_HANDOFF
        val claim = synchronized(this) { claimLocked(host) }
            ?: return CiphertextDeliveryResult.NO_HANDOFF

        val boundaryCrossed = try {
            claim.markCommitUncertain()
        } catch (_: RuntimeException) {
            false
        }
        if (!boundaryCrossed) {
            synchronized(this) { consumeLocked(claim) }
            claim.close()
            return CiphertextDeliveryResult.NO_HANDOFF
        }

        val accepted = try {
            committer.commit(claim.ciphertext)
        } catch (_: RuntimeException) {
            false
        }
        if (!accepted) {
            // A false result is ambiguous across Binder: the host may have applied the text before
            // the response was lost. Consume the one-shot capability and retain the durable
            // COMMIT_UNCERTAIN record for diagnosis; it must never be retried automatically.
            synchronized(this) { consumeLocked(claim) }
            claim.close()
            return CiphertextDeliveryResult.HOST_COMMIT_UNCERTAIN
        }

        val operationId = claim.operationId()
        // Stop automatic retries before touching storage: the external editor already accepted it.
        synchronized(this) { consumeLocked(claim) }
        val completed = try {
            completion.complete(operationId)
        } catch (_: RuntimeException) {
            false
        } finally {
            operationId.fill(0)
            claim.close()
        }
        return if (completed) {
            CiphertextDeliveryResult.COMMITTED_AND_COMPLETED
        } else {
            // The encrypted durable record remains available for explicit recovery; never auto-retry.
            CiphertextDeliveryResult.COMMITTED_PENDING_CLEANUP
        }
    }

    @Synchronized
    internal fun hasSessionForTest(): Boolean = liveSessionLocked() != null

    private fun claimLocked(host: HostEditorScope): CiphertextClaim? {
        val current = liveSessionLocked() ?: return null
        if (!current.host.matches(host) || current.activeClaim != null) return null
        val operationId = current.operationId ?: return null
        val ciphertext = current.ciphertext ?: return null
        val boundary = current.commitBoundary ?: return null
        return CiphertextClaim(operationId, ciphertext, boundary).also { current.activeClaim = it }
    }

    private fun consumeLocked(claim: CiphertextClaim) {
        val current = session
        if (current?.activeClaim === claim) clearLocked()
    }

    private fun liveSessionLocked(): HandoffSession? {
        val current = session ?: return null
        if (System.nanoTime() - current.expiresAtNanos >= 0) {
            clearLocked()
            return null
        }
        return current
    }

    private fun clearLocked() {
        session?.wipe()
        session = null
    }

    private fun deadlineNanos(): Long = System.nanoTime() + SESSION_TTL_NANOS

    private fun editorScope(
        packageName: String?,
        uid: Int,
        connectionToken: IBinder?,
        connectionIdentity: Any?,
        fieldId: Int,
        fieldName: String?,
        inputType: Int,
        imeOptions: Int,
        privateImeOptions: String?,
        initialSelectionStart: Int,
        initialSelectionEnd: Int,
    ): HostEditorScope? {
        val normalizedPackage = packageName?.takeIf { it.isNotBlank() } ?: return null
        if (uid < 0 || connectionIdentity == null) return null
        return HostEditorScope(
            normalizedPackage,
            uid,
            fieldId,
            fieldName,
            inputType,
            imeOptions,
            privateImeOptions,
            initialSelectionStart,
            initialSelectionEnd,
            connectionIdentity,
        )
    }

    private const val SESSION_TTL_NANOS = 15L * 60L * 1_000_000_000L
}

private class CiphertextClaim(
    operationId: ByteArray,
    val ciphertext: String,
    private val boundary: OutboundCommitBoundary,
) : AutoCloseable {
    private var closed = false
    private var id = operationId.copyOf()

    fun operationId(): ByteArray = id.copyOf()
    fun markCommitUncertain(): Boolean = if (closed) false else boundary.markUncertain()

    override fun close() {
        if (closed) return
        closed = true
        id.fill(0)
        id = ByteArray(0)
        boundary.close()
    }
}
