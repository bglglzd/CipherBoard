package org.cipherboard.securestorage

import java.nio.ByteBuffer

enum class PendingOutboundState {
    READY,
    COMMIT_UNCERTAIN,
}

internal data class DecodedPendingOutbound(
    val contactId: ByteArray,
    val operationId: ByteArray,
    val ciphertext: ByteArray,
    val state: PendingOutboundState,
)

/** Versioned plaintext encoding inside the AEAD-protected pending-outbound record. */
internal object PendingOutboundRecordCodec {
    fun encodeV2(
        contactId: ByteArray,
        operationId: ByteArray,
        ciphertext: ByteArray,
        state: PendingOutboundState,
    ): ByteArray {
        val contactBoundSize = PendingRecordCodec.encodedSize(contactId, ciphertext.size)
        val stateBoundSize = Math.addExact(Int.SIZE_BYTES, contactBoundSize)
        PendingRecordCodec.encodedSize(operationId, stateBoundSize)
        val contactBound = PendingRecordCodec.encode(contactId, ciphertext)
        return try {
            val stateBound = ByteBuffer.allocate(stateBoundSize)
                .putInt(state.wireValue)
                .put(contactBound)
                .array()
            try {
                PendingRecordCodec.encode(operationId, stateBound)
            } finally {
                stateBound.wipe()
            }
        } finally {
            contactBound.wipe()
        }
    }

    @Throws(VaultCorruptException::class)
    fun decode(schemaVersion: Int, encoded: ByteArray): DecodedPendingOutbound {
        return when (schemaVersion) {
            LEGACY_SCHEMA_VERSION -> decodeV1(encoded)
            CURRENT_SCHEMA_VERSION -> decodeV2(encoded)
            else -> throw VaultCorruptException("Unknown pending outbound schema")
        }
    }

    private fun decodeV1(encoded: ByteArray): DecodedPendingOutbound {
        val (operationId, contactBound) = PendingRecordCodec.decode(encoded)
        return try {
            val (contactId, ciphertext) = PendingRecordCodec.decode(contactBound)
            // Schema 1 did not persist whether host commitText() had already been attempted.
            // After an upgrade, automatic retry could therefore duplicate a delivered message.
            DecodedPendingOutbound(
                contactId,
                operationId,
                ciphertext,
                PendingOutboundState.COMMIT_UNCERTAIN,
            )
        } catch (error: Throwable) {
            operationId.wipe()
            throw error
        } finally {
            contactBound.wipe()
        }
    }

    private fun decodeV2(encoded: ByteArray): DecodedPendingOutbound {
        val (operationId, stateBound) = PendingRecordCodec.decode(encoded)
        return try {
            if (stateBound.size <= Int.SIZE_BYTES) {
                throw VaultCorruptException("Pending outbound state is truncated")
            }
            val stateBuffer = ByteBuffer.wrap(stateBound)
            val state = when (stateBuffer.int) {
                READY_WIRE_VALUE -> PendingOutboundState.READY
                COMMIT_UNCERTAIN_WIRE_VALUE -> PendingOutboundState.COMMIT_UNCERTAIN
                else -> throw VaultCorruptException("Unknown pending outbound state")
            }
            val contactBound = ByteArray(stateBuffer.remaining()).also(stateBuffer::get)
            try {
                val (contactId, ciphertext) = PendingRecordCodec.decode(contactBound)
                DecodedPendingOutbound(contactId, operationId, ciphertext, state)
            } finally {
                contactBound.wipe()
            }
        } catch (error: Throwable) {
            operationId.wipe()
            throw error
        } finally {
            stateBound.wipe()
        }
    }

    private val PendingOutboundState.wireValue: Int
        get() = when (this) {
            PendingOutboundState.READY -> READY_WIRE_VALUE
            PendingOutboundState.COMMIT_UNCERTAIN -> COMMIT_UNCERTAIN_WIRE_VALUE
        }

    const val LEGACY_SCHEMA_VERSION = 1
    const val CURRENT_SCHEMA_VERSION = 2
    private const val READY_WIRE_VALUE = 1
    private const val COMMIT_UNCERTAIN_WIRE_VALUE = 2
}
