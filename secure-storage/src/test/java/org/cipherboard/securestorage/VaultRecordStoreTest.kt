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
    private lateinit var lock: VaultLockController
    private lateinit var store: VaultRecordStore
    private val contactId = ByteArray(16) { (it + 1).toByte() }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
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
        assertArrayEquals(operationId, pending.single().operationId)
        assertArrayEquals(ciphertext, pending.single().ciphertext)
        assertTrue(store.completeOutbound(operationId))
        assertTrue(store.listPendingOutbound().isEmpty())
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

        assertEquals(
            AtomicInboundResult.COMMITTED,
            store.commitInbound(
                contactId, 1, 1, secret("state-2"), messageId, secret("display plaintext"),
            ),
        )
        assertTrue(store.isReplay(contactId, messageId))
        store.readPendingDisplay(messageId)!!.use { display ->
            display.plaintext.consume {
                assertArrayEquals("display plaintext".encodeToByteArray(), it)
            }
        }

        assertEquals(
            AtomicInboundResult.REPLAY,
            store.commitInbound(
                contactId, 2, 1, secret("must-not-commit"), messageId, secret("duplicate"),
            ),
        )
        assertEquals(2, store.readRatchet(contactId)!!.use { it.revision })

        val differentMessage = ByteArray(16) { 9 }
        assertEquals(
            AtomicInboundResult.REVISION_CONFLICT,
            store.commitInbound(
                contactId, 1, 1, secret("must-not-commit"), differentMessage, secret("not shown"),
            ),
        )
        assertFalse(store.isReplay(contactId, differentMessage))
        assertEquals(2, store.readRatchet(contactId)!!.use { it.revision })
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

    private fun secret(value: String) = OwnedSecret(value.encodeToByteArray())
}
