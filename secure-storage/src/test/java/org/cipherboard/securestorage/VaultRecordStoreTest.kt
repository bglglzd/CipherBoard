package org.cipherboard.securestorage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultRecordStoreTest {
    private lateinit var context: Context
    private lateinit var lock: VaultLockController
    private lateinit var store: VaultRecordStore
    private val contactId = ByteArray(16) { (it + 1).toByte() }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        lock = VaultLockController(clock = MonotonicClock { 0 })
        lock.unlock(
            UnlockedVaultMaterial(
                KeyProtectionInfo(
                    KeystoreSecurityLevel.TRUSTED_ENVIRONMENT,
                    true,
                    false,
                    VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
                ),
                OwnedSecret(ByteArray(32) { 0x33 }),
            ),
        )
        store = VaultRecordStore(context, lock)
        store.destroyAll()
    }

    @After
    fun tearDown() {
        store.destroyAll()
        store.close()
        lock.close()
    }

    @Test
    fun outboundCommitAdvancesRatchetAndPersistsRetryableCiphertext() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val operationId = ByteArray(16) { 4 }
        val ciphertext = "CB1:ciphertext".encodeToByteArray()

        store.commitOutbound(contactId, 1, 1, secret("state-2"), operationId, ciphertext)

        store.readRatchet(contactId)!!.use { ratchet ->
            assertEquals(2, ratchet.revision)
            ratchet.secret.consume { assertArrayEquals("state-2".encodeToByteArray(), it) }
        }
        val pending = store.listPendingOutbound()
        assertEquals(1, pending.size)
        assertArrayEquals(contactId, pending.single().contactId)
        assertArrayEquals(operationId, pending.single().operationId)
        assertArrayEquals(ciphertext, pending.single().ciphertext)
        assertEquals(PendingOutboundState.READY, pending.single().state)
        assertTrue(store.completeOutbound(operationId))
        assertTrue(store.listPendingOutbound().isEmpty())
    }

    @Test
    fun outboundCommitBoundaryPersistsAndCannotBeCrossedTwice() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val operationId = ByteArray(16) { 5 }
        store.commitOutbound(
            contactId,
            1,
            1,
            secret("state-2"),
            operationId,
            "CB1:uncertain".encodeToByteArray(),
        )

        assertTrue(store.markOutboundCommitUncertain(operationId))
        assertFalse(store.markOutboundCommitUncertain(operationId))
        assertEquals(PendingOutboundState.COMMIT_UNCERTAIN, store.listPendingOutbound().single().state)

        store.close()
        store = VaultRecordStore(context, lock)
        val recovered = store.listPendingOutbound().single()
        assertEquals(PendingOutboundState.COMMIT_UNCERTAIN, recovered.state)
        assertFalse(store.markOutboundCommitUncertain(operationId))
        operationId.fill(0)
    }

    @Test
    fun staleOutboundRevisionRollsBackPendingInsert() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))

        assertThrows(RatchetRevisionConflictException::class.java) {
            store.commitOutbound(
                contactId,
                9,
                1,
                secret("must-not-commit"),
                ByteArray(16) { 8 },
                "CB1:pending".encodeToByteArray(),
            )
        }

        assertTrue(store.listPendingOutbound().isEmpty())
        assertEquals(1, store.readRatchet(contactId)!!.use { it.revision })
    }

    @Test
    fun inboundReplayAndRevisionConflictsDoNotPartiallyAdvanceState() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val messageId = ByteArray(16) { 7 }
        val ciphertextDigest = ByteArray(32) { 6 }

        assertEquals(
            AtomicInboundResult.COMMITTED,
            store.commitInbound(
                contactId, 1, 1, secret("state-2"), messageId, ciphertextDigest,
                secret("display plaintext"),
            ),
        )
        assertTrue(store.isReplay(contactId, messageId))
        store.readPendingDisplay(contactId, messageId)!!.use { display ->
            assertArrayEquals(ciphertextDigest, display.ciphertextDigest)
            display.plaintext.consume {
                assertArrayEquals("display plaintext".encodeToByteArray(), it)
            }
        }
        assertThrows(VaultCorruptException::class.java) {
            store.readPendingDisplay(ByteArray(contactId.size) { 99 }, messageId)
        }

        assertEquals(
            AtomicInboundResult.REPLAY,
            store.commitInbound(
                contactId, 2, 1, secret("must-not-commit"), messageId, ciphertextDigest,
                secret("duplicate"),
            ),
        )
        assertEquals(2, store.readRatchet(contactId)!!.use { it.revision })

        val differentMessage = ByteArray(16) { 9 }
        assertEquals(
            AtomicInboundResult.REVISION_CONFLICT,
            store.commitInbound(
                contactId, 1, 1, secret("must-not-commit"), differentMessage, ciphertextDigest,
                secret("not shown"),
            ),
        )
        assertFalse(store.isReplay(contactId, differentMessage))
        assertEquals(2, store.readRatchet(contactId)!!.use { it.revision })
    }

    @Test
    fun replayMarkersAreBoundedPerContactAndRetainNewestMessage() {
        val ids = (0 until 20).map { value ->
            ByteArray(16).also { bytes ->
                bytes[12] = (value ushr 24).toByte()
                bytes[13] = (value ushr 16).toByte()
                bytes[14] = (value ushr 8).toByte()
                bytes[15] = value.toByte()
            }
        }
        ids.forEach { assertTrue(store.insertReplayMarkerForTesting(contactId, it, 16)) }

        assertEquals(16, store.replayMarkerCountForTesting(contactId))
        assertFalse(store.isReplay(contactId, ids.first()))
        assertTrue(store.isReplay(contactId, ids.last()))
        assertFalse(store.insertReplayMarkerForTesting(contactId, ids.last(), 16))
        assertEquals(16, store.replayMarkerCountForTesting(contactId))
    }

    @Test
    fun lockedVaultCannotReadOrWriteEncryptedRecords() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        lock.lock()
        assertThrows(VaultLockedException::class.java) { store.readRatchet(contactId) }
        assertThrows(VaultLockedException::class.java) {
            store.commitOutbound(
                contactId, 1, 1, secret("state-2"), ByteArray(16) { 2 }, ByteArray(1),
            )
        }
    }

    @Test
    fun lockedVaultCanDeleteEncryptedPendingDisplayWithoutDecryptingIt() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val messageId = ByteArray(16) { 12 }
        assertEquals(
            AtomicInboundResult.COMMITTED,
            store.commitInbound(
                contactId,
                1,
                1,
                secret("state-2"),
                messageId,
                ByteArray(32) { 13 },
                secret("temporary plaintext"),
            ),
        )

        lock.lock()

        assertTrue(store.deletePendingDisplay(messageId))
        assertThrows(VaultLockedException::class.java) {
            store.readPendingDisplay(contactId, messageId)
        }
    }

    @Test
    fun expiredPendingDisplayCanBePurgedWithoutUnlockingVault() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val messageId = ByteArray(16) { 0x21 }
        assertEquals(
            AtomicInboundResult.COMMITTED,
            store.commitInbound(
                contactId,
                1,
                1,
                secret("state-2"),
                messageId,
                ByteArray(32) { 0x22 },
                secret("short crash recovery plaintext"),
            ),
        )
        lock.lock()

        assertEquals(1, store.purgePendingDisplaysCreatedAtOrBefore(Long.MAX_VALUE))
        assertEquals(0, store.purgePendingDisplaysCreatedAtOrBefore(Long.MAX_VALUE))
    }

    @Test
    fun rejectedOversizedPendingRecordsStillWipeTransferredSecrets() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val outboundRatchet = ByteArray(64) { 0x61 }
        assertThrows(IllegalArgumentException::class.java) {
            store.commitOutbound(
                contactId,
                1,
                1,
                OwnedSecret.takeOwnership(outboundRatchet),
                ByteArray(16) { 0x62 },
                ByteArray(RecordCrypto.MAX_RECORD_BYTES),
            )
        }
        assertTrue(outboundRatchet.all { it == 0.toByte() })

        val inboundRatchet = ByteArray(64) { 0x63 }
        val inboundPlaintext = ByteArray(RecordCrypto.MAX_RECORD_BYTES) { 0x64 }
        assertThrows(IllegalArgumentException::class.java) {
            store.commitInbound(
                contactId,
                1,
                1,
                OwnedSecret.takeOwnership(inboundRatchet),
                ByteArray(16) { 0x65 },
                ByteArray(32) { 0x66 },
                OwnedSecret.takeOwnership(inboundPlaintext),
            )
        }
        assertTrue(inboundRatchet.all { it == 0.toByte() })
        assertTrue(inboundPlaintext.all { it == 0.toByte() })
        assertEquals(1, store.readRatchet(contactId)!!.use { it.revision })
        assertTrue(store.listPendingOutbound().isEmpty())
    }

    @Test
    fun staleContactMutationRollsBackRatchetPendingAndReplayAtomically() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val contactKey = IdentifierCodec.domainKey("vault-contact", contactId)
        val ownerKey = IdentifierCodec.contactKey(contactId)
        val initialContact = "contact-revision-1".encodeToByteArray()
        assertTrue(
            store.applyDomainMutations(
                listOf(DomainMutation.Put(11, contactKey, ownerKey, 2, 0, initialContact)),
            ),
        )
        initialContact.wipe()
        val staleContact = "stale-contact-update".encodeToByteArray()
        val staleMutation = DomainMutation.Put(11, contactKey, ownerKey, 2, 2, staleContact)

        assertThrows(RatchetRevisionConflictException::class.java) {
            store.commitOutboundWithDomainMutation(
                contactId,
                1,
                1,
                secret("state-2"),
                ByteArray(16) { 0x71 },
                "CB1:must-rollback".encodeToByteArray(),
                staleMutation,
            )
        }
        assertEquals(1, store.readRatchet(contactId)!!.use { it.revision })
        assertEquals(1, store.readDomainRecord(11, contactKey)!!.use { it.revision })
        assertTrue(store.listPendingOutbound().isEmpty())

        val messageId = ByteArray(16) { 0x72 }
        assertEquals(
            AtomicInboundResult.REVISION_CONFLICT,
            store.commitInboundWithDomainMutation(
                contactId,
                1,
                1,
                secret("state-2"),
                messageId,
                ByteArray(32) { 0x73 },
                secret("must-not-display"),
                staleMutation,
            ),
        )
        assertEquals(1, store.readRatchet(contactId)!!.use { it.revision })
        assertEquals(1, store.readDomainRecord(11, contactKey)!!.use { it.revision })
        assertFalse(store.isReplay(contactId, messageId))
        assertTrue(store.readPendingDisplay(contactId, messageId) == null)
        staleContact.wipe()
    }

    @Test
    fun domainMutationCannotCrossContactOwnershipBoundary() {
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("state-1")))
        val otherContact = ByteArray(16) { 0x7a }
        val nextState = ByteArray(32) { 0x7b }
        val mutation = DomainMutation.Put(
            11,
            IdentifierCodec.domainKey("vault-contact", otherContact),
            IdentifierCodec.contactKey(otherContact),
            2,
            1,
            ByteArray(16),
        )

        assertThrows(IllegalArgumentException::class.java) {
            store.commitOutboundWithDomainMutation(
                contactId,
                1,
                1,
                OwnedSecret.takeOwnership(nextState),
                ByteArray(16) { 0x7c },
                "CB1:cross-owner".encodeToByteArray(),
                mutation,
            )
        }
        assertTrue(nextState.all { it == 0.toByte() })
        assertEquals(1, store.readRatchet(contactId)!!.use { it.revision })
        assertTrue(store.listPendingOutbound().isEmpty())
    }

    private fun secret(value: String) = OwnedSecret(value.encodeToByteArray())
}
