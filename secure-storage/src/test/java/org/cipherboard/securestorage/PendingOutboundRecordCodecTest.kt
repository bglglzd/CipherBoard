package org.cipherboard.securestorage

import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PendingOutboundRecordCodecTest {
    private val contactId = ByteArray(16) { (it + 1).toByte() }
    private val operationId = ByteArray(16) { (it + 20).toByte() }
    private val ciphertext = "CB1:legacy".encodeToByteArray()

    @Test
    fun `legacy schema one decodes as uncertain to prevent duplicate delivery`() {
        val contactBound = PendingRecordCodec.encode(contactId, ciphertext)
        val legacy = try {
            PendingRecordCodec.encode(operationId, contactBound)
        } finally {
            contactBound.wipe()
        }

        try {
            val decoded = PendingOutboundRecordCodec.decode(
                PendingOutboundRecordCodec.LEGACY_SCHEMA_VERSION,
                legacy,
            )
            try {
                assertArrayEquals(contactId, decoded.contactId)
                assertArrayEquals(operationId, decoded.operationId)
                assertArrayEquals(ciphertext, decoded.ciphertext)
                assertEquals(PendingOutboundState.COMMIT_UNCERTAIN, decoded.state)
            } finally {
                decoded.contactId.wipe()
                decoded.operationId.wipe()
                decoded.ciphertext.wipe()
            }
        } finally {
            legacy.wipe()
        }
    }

    @Test
    fun `schema two round trips commit uncertain state`() {
        val encoded = PendingOutboundRecordCodec.encodeV2(
            contactId,
            operationId,
            ciphertext,
            PendingOutboundState.COMMIT_UNCERTAIN,
        )
        try {
            val decoded = PendingOutboundRecordCodec.decode(
                PendingOutboundRecordCodec.CURRENT_SCHEMA_VERSION,
                encoded,
            )
            try {
                assertEquals(PendingOutboundState.COMMIT_UNCERTAIN, decoded.state)
                assertArrayEquals(ciphertext, decoded.ciphertext)
            } finally {
                decoded.contactId.wipe()
                decoded.operationId.wipe()
                decoded.ciphertext.wipe()
            }
        } finally {
            encoded.wipe()
        }
    }

    @Test
    fun `unknown encrypted record schema is rejected`() {
        assertThrows(VaultCorruptException::class.java) {
            PendingOutboundRecordCodec.decode(99, ByteArray(32))
        }
    }

    @Test
    fun `unknown schema two state is rejected`() {
        val encoded = PendingOutboundRecordCodec.encodeV2(
            contactId,
            operationId,
            ciphertext,
            PendingOutboundState.READY,
        )
        try {
            val stateOffset = Int.SIZE_BYTES * 3 + operationId.size
            ByteBuffer.wrap(encoded).putInt(stateOffset, 99)
            assertThrows(VaultCorruptException::class.java) {
                PendingOutboundRecordCodec.decode(
                    PendingOutboundRecordCodec.CURRENT_SCHEMA_VERSION,
                    encoded,
                )
            }
        } finally {
            encoded.wipe()
        }
    }
}
