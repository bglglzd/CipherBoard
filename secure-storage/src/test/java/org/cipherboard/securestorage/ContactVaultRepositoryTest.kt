package org.cipherboard.securestorage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ContactVaultRepositoryTest {
    private lateinit var context: Context
    private lateinit var lock: VaultLockController
    private lateinit var store: VaultRecordStore
    private lateinit var repository: ContactVaultRepository
    private val pairingId = ByteArray(16) { (it + 10).toByte() }
    private val contactId = ByteArray(16) { (it + 30).toByte() }

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
                OwnedSecret(ByteArray(32) { 0x55 }),
            ),
        )
        store = VaultRecordStore(context, lock)
        store.destroyAll()
        repository = ContactVaultRepository(store)
    }

    @After
    fun tearDown() {
        store.destroyAll()
        store.close()
        lock.close()
    }

    @Test
    fun ownerAndPendingPairingAreVersionedAndQueryableByStatusAndExpiry() {
        owner(1).use { assertTrue(repository.createOwnerAccount(it)) }
        owner(2).use { updated ->
            pending().use { assertTrue(repository.stagePendingPairing(1, updated, it)) }
        }

        repository.readOwnerAccount()!!.use {
            assertEquals(2, it.revision)
            assertEquals("Локальный владелец", it.value.localOwnerName)
            assertArrayEquals(ByteArray(128) { 2 }, it.value.accountState)
        }
        repository.listActivePendingPairings(NOW, 5).useAll { active ->
            assertEquals(1, active.size)
            assertEquals(OneShotStatus.ACTIVE, active.single().value.oneShotStatus)
        }
        repository.listPendingPairings(
            status = OneShotStatus.ACTIVE,
            expiresNotAfterEpochMillis = NOW + 100,
        ).useAll { assertTrue(it.isEmpty()) }
    }

    @Test
    fun staleAccountRevisionRollsBackPendingPairingInsert() {
        owner(1).use { assertTrue(repository.createOwnerAccount(it)) }
        owner(2).use { updated ->
            pending().use { assertFalse(repository.stagePendingPairing(9, updated, it)) }
        }

        assertNull(repository.readPendingPairing(pairingId))
        repository.readOwnerAccount()!!.use { assertEquals(1, it.revision) }
    }

    @Test
    fun conflictOnFinalPairingStepRollsBackAccountAndOneShotConsumption() {
        stagePairing()

        owner(3).use { updated ->
            contact().use { contact ->
                assertFalse(
                    repository.completePairing(
                        pairingId,
                        expectedPairingRevision = 1,
                        expectedOwnerRevision = 2,
                        expectedContactRevision = 1,
                        nowEpochMillis = NOW,
                        updatedOwnerAccount = updated,
                        contact = contact,
                        expectedRatchetRevision = 0,
                        ratchetSchemaVersion = 1,
                        initialRatchetState = secret("conflicting-ratchet"),
                    ),
                )
            }
        }

        repository.readOwnerAccount()!!.use { assertEquals(2, it.revision) }
        repository.readPendingPairing(pairingId)!!.use {
            assertEquals(1, it.revision)
            assertEquals(OneShotStatus.ACTIVE, it.value.oneShotStatus)
        }
        assertNull(repository.readContact(contactId))
    }

    @Test
    fun initialRatchetConflictRollsBackOwnerPairingAndContact() {
        stagePairing()
        assertTrue(store.insertInitialRatchet(contactId, 1, secret("orphan-ratchet")))

        owner(3).use { updated ->
            contact().use { contact ->
                assertFalse(
                    repository.completePairing(
                        pairingId,
                        expectedPairingRevision = 1,
                        expectedOwnerRevision = 2,
                        expectedContactRevision = 0,
                        nowEpochMillis = NOW,
                        updatedOwnerAccount = updated,
                        contact = contact,
                        expectedRatchetRevision = 0,
                        ratchetSchemaVersion = 1,
                        initialRatchetState = secret("must-not-commit"),
                    ),
                )
            }
        }

        repository.readOwnerAccount()!!.use { assertEquals(2, it.revision) }
        repository.readPendingPairing(pairingId)!!.use {
            assertEquals(1, it.revision)
            assertEquals(OneShotStatus.ACTIVE, it.value.oneShotStatus)
        }
        assertNull(repository.readContact(contactId))
        store.readRatchet(contactId)!!.use { ratchet ->
            assertEquals(1, ratchet.revision)
            ratchet.secret.consume { assertArrayEquals("orphan-ratchet".encodeToByteArray(), it) }
        }
    }

    @Test
    fun completionContactUpdatesAndDeletionUseOptimisticAtomicState() {
        stagePairing()
        owner(3).use { updated ->
            contact().use { contact ->
                assertTrue(
                    repository.completePairing(
                        pairingId,
                        expectedPairingRevision = 1,
                        expectedOwnerRevision = 2,
                        expectedContactRevision = 0,
                        nowEpochMillis = NOW,
                        updatedOwnerAccount = updated,
                        contact = contact,
                        expectedRatchetRevision = 0,
                        ratchetSchemaVersion = 1,
                        initialRatchetState = secret("initial-ratchet"),
                    ),
                )
            }
        }

        repository.readPendingPairing(pairingId)!!.use {
            assertEquals(2, it.revision)
            assertEquals(OneShotStatus.CONSUMED, it.value.oneShotStatus)
            assertArrayEquals(byteArrayOf(0), it.value.payload)
        }
        repository.listContacts().useAll { contacts ->
            assertEquals(1, contacts.size)
            assertEquals("Боб 🔐", contacts.single().value.localName)
        }
        store.readRatchet(contactId)!!.use { ratchet ->
            assertEquals(1, ratchet.revision)
            ratchet.secret.consume { assertArrayEquals("initial-ratchet".encodeToByteArray(), it) }
        }
        assertTrue(repository.renameContact(contactId, 1, "Боб локально"))
        assertFalse(repository.renameContact(contactId, 1, "stale"))
        assertTrue(
            repository.updateContactStatus(
                contactId,
                expectedRevision = 2,
                verificationStatus = ContactVerificationStatus.KEY_CHANGED,
                requiresRepairing = true,
                sessionError = false,
                keyChanged = true,
                lastActiveAtEpochMillis = NOW + 1,
            ),
        )
        assertTrue(repository.destroyContactSession(contactId, 3, 1, NOW + 2))
        repository.readContact(contactId)!!.use {
            assertEquals(4, it.revision)
            assertEquals(ContactVerificationStatus.PAIRING_REQUIRED, it.value.verificationStatus)
            assertTrue(it.value.requiresRepairing)
        }

        assertTrue(repository.deleteContact(contactId, 4))
        assertNull(repository.readContact(contactId))
        assertNull(store.readRatchet(contactId))
    }

    @Test
    fun activePairingCannotBeConsumedTwiceOrAfterExpiry() {
        stagePairing()
        owner(3).use { updated ->
            contact().use { contact ->
                assertFalse(
                    repository.completePairing(
                        pairingId,
                        1,
                        2,
                        0,
                        NOW + 301_000,
                        updated,
                        contact,
                        0,
                        1,
                        secret("expired-ratchet"),
                    ),
                )
            }
        }
        repository.readPendingPairing(pairingId)!!.use {
            assertEquals(OneShotStatus.ACTIVE, it.value.oneShotStatus)
            assertEquals(1, it.revision)
        }

        assertTrue(repository.expirePendingPairing(pairingId, 1, NOW + 301_000))
        assertFalse(repository.cancelPendingPairing(pairingId, 2))
        repository.readPendingPairing(pairingId)!!.use {
            assertEquals(OneShotStatus.EXPIRED, it.value.oneShotStatus)
            assertArrayEquals(byteArrayOf(0), it.value.payload)
        }
        repository.listActivePendingPairings(NOW).useAll { assertTrue(it.isEmpty()) }
    }

    @Test
    fun destroySessionPurgesState() {
        stagePairing()
        owner(3).use { updated ->
            contact().use { contact ->
                assertTrue(
                    repository.completePairing(
                        pairingId,
                        1,
                        2,
                        0,
                        NOW,
                        updated,
                        contact,
                        0,
                        1,
                        secret("state-1"),
                    ),
                )
            }
        }
        val outboundId = ByteArray(16) { 0x41 }
        store.commitOutbound(
            contactId,
            1,
            1,
            secret("state-2"),
            outboundId,
            "CB1:pending".encodeToByteArray(),
        )
        val inboundId = ByteArray(16) { 0x42 }
        assertEquals(
            AtomicInboundResult.COMMITTED,
            store.commitInbound(
                contactId,
                2,
                1,
                secret("state-3"),
                inboundId,
                secret("temporary display"),
            ),
        )

        assertTrue(repository.destroyContactSession(contactId, 1, 3, NOW + 1))

        repository.readContact(contactId)!!.use {
            assertEquals(2, it.revision)
            assertEquals(ContactVerificationStatus.PAIRING_REQUIRED, it.value.verificationStatus)
        }
        assertNull(store.readRatchet(contactId))
        assertTrue(store.listPendingOutbound().isEmpty())
        assertNull(store.readPendingDisplay(inboundId))
        assertFalse(store.isReplay(contactId, inboundId))
    }

    @Test
    fun localNamesAndSessionStateDoNotAppearInDatabaseFiles() {
        val localName = "PRIVATE-CONTACT-NAME-9375"
        val sessionMarker = "PRIVATE-SESSION-STATE-2841".encodeToByteArray()
        stagePairing()
        owner(3).use { updated ->
            contact(localName).use { contact ->
                val ratchet = OwnedSecret(sessionMarker.copyOf())
                assertTrue(repository.completePairing(pairingId, 1, 2, 0, NOW, updated, contact, 0, 1, ratchet))
            }
        }

        val forbidden = listOf(localName.encodeToByteArray(), sessionMarker)
        val databaseDirectory = context.noBackupFilesDir.resolve("cipherboard_vault")
        try {
            databaseDirectory.walkTopDown().filter { it.isFile }.forEach { file ->
                val bytes = file.readBytes()
                try {
                    forbidden.forEach { marker -> assertFalse(bytes.containsSequence(marker)) }
                } finally {
                    bytes.wipe()
                }
            }
        } finally {
            forbidden.forEach { it.wipe() }
        }
    }

    private fun stagePairing() {
        owner(1).use { assertTrue(repository.createOwnerAccount(it)) }
        owner(2).use { updated ->
            pending().use { assertTrue(repository.stagePendingPairing(1, updated, it)) }
        }
    }

    private fun owner(marker: Byte) = OwnerIdentityAccountState(
        localOwnerName = "Локальный владелец",
        accountState = ByteArray(128) { marker },
        identityFingerprint = ByteArray(32) { (marker + it).toByte() },
        protocolVersion = 1,
        createdAtEpochMillis = NOW,
    )

    private fun pending() = PendingPairingState(
        type = PendingPairingType.OFFER,
        pairingId = pairingId,
        createdAtEpochMillis = NOW,
        expiresAtEpochMillis = NOW + 300_000,
        nonce = ByteArray(32) { (it + 1).toByte() },
        transcriptHash = ByteArray(32) { (it + 2).toByte() },
        oneShotStatus = OneShotStatus.ACTIVE,
        protocolVersion = 1,
        payload = ByteArray(96) { (it + 3).toByte() },
    )

    private fun contact(localName: String = "Боб 🔐") = ContactVaultEntry(
        internalId = contactId,
        localName = localName,
        remoteIdentityFingerprint = ByteArray(32) { (it + 4).toByte() },
        remoteSessionTag = ByteArray(16) { (it + 5).toByte() },
        verificationStatus = ContactVerificationStatus.VERIFIED,
        pairedAtEpochMillis = NOW,
        lastActiveAtEpochMillis = NOW,
        protocolVersion = 1,
        safetyNumber = "12345 67890 12345 67890",
        safetyCode = "amber beacon cedar delta",
        requiresRepairing = false,
        sessionError = false,
        keyChanged = false,
    )

    private fun secret(value: String) = OwnedSecret(value.encodeToByteArray())

    private inline fun <T : AutoCloseable, R> List<T>.useAll(block: (List<T>) -> R): R = try {
        block(this)
    } finally {
        forEach { it.close() }
    }

    private fun ByteArray.containsSequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        for (start in 0..size - needle.size) {
            var matches = true
            for (offset in needle.indices) {
                if (this[start + offset] != needle[offset]) {
                    matches = false
                    break
                }
            }
            if (matches) return true
        }
        return false
    }

    companion object {
        private const val NOW = 1_700_000_000_000L
    }
}
