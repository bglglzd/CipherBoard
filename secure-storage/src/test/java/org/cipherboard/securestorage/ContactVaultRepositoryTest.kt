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
    fun oldTerminalPairingIsPrunedAndNewestActiveRecordRemainsDiscoverable() {
        owner(1).use { assertTrue(repository.createOwnerAccount(it)) }
        val oldId = ByteArray(16) { 0x2a }
        val oldCreated = NOW - 8L * 24 * 60 * 60 * 1_000
        owner(2).use { updated ->
            pending(oldId, oldCreated).use {
                assertTrue(repository.stagePendingPairing(1, updated, it))
            }
        }
        assertTrue(repository.cancelPendingPairing(oldId, 1))

        val newId = ByteArray(16) { 0x2b }
        owner(3).use { updated ->
            pending(newId, NOW).use {
                assertTrue(repository.stagePendingPairing(2, updated, it))
            }
        }

        assertNull(repository.readPendingPairing(oldId))
        repository.listActivePendingPairings(NOW).useAll { active ->
            assertEquals(1, active.size)
            assertArrayEquals(newId, active.single().value.pairingId)
        }
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
                ByteArray(32) { 0x43 },
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
        assertNull(store.readPendingDisplay(contactId, inboundId))
        assertFalse(store.isReplay(contactId, inboundId))
    }

    @Test
    fun messageCommitsAdvanceContactActivityWithRatchetAndPendingRecords() {
        stagePairing()
        owner(3).use { updated ->
            contact().use { contact ->
                assertTrue(
                    repository.completePairing(
                        pairingId, 1, 2, 0, NOW, updated, contact, 0, 1, secret("state-1"),
                    ),
                )
            }
        }

        val outboundId = ByteArray(16) { 0x51 }
        secret("state-2").use { nextState ->
            repository.commitOutbound(
                contactId,
                expectedContactRevision = 1,
                lastActiveAtEpochMillis = NOW + 100,
                expectedRatchetRevision = 1,
                ratchetSchemaVersion = 1,
                newRatchetState = nextState,
                operationId = outboundId,
                pendingCiphertext = "CB1:atomic-outbound".encodeToByteArray(),
            )
        }
        repository.readContact(contactId)!!.use {
            assertEquals(2, it.revision)
            assertEquals(NOW + 100, it.value.lastActiveAtEpochMillis)
        }
        store.readRatchet(contactId)!!.use { assertEquals(2, it.revision) }
        assertEquals(1, store.listPendingOutbound().size)

        val inboundId = ByteArray(16) { 0x52 }
        val inboundResult = secret("state-3").use { nextState ->
            secret("temporary plaintext").use { plaintext ->
                repository.commitInbound(
                    contactId,
                    expectedContactRevision = 2,
                    lastActiveAtEpochMillis = NOW + 200,
                    expectedRatchetRevision = 2,
                    ratchetSchemaVersion = 1,
                    newRatchetState = nextState,
                    messageId = inboundId,
                    ciphertextDigest = ByteArray(32) { 0x53 },
                    pendingPlaintext = plaintext,
                )
            }
        }
        assertEquals(AtomicInboundResult.COMMITTED, inboundResult)
        repository.readContact(contactId)!!.use {
            assertEquals(3, it.revision)
            assertEquals(NOW + 200, it.value.lastActiveAtEpochMillis)
        }
        store.readRatchet(contactId)!!.use { assertEquals(3, it.revision) }
        assertTrue(store.isReplay(contactId, inboundId))
        store.readPendingDisplay(contactId, inboundId)!!.close()
    }

    @Test
    fun missingContactFailureStillWipesTransferredMessageSecrets() {
        val missingId = ByteArray(16) { 0x54 }
        val outboundState = ByteArray(64) { 0x55 }
        org.junit.Assert.assertThrows(RatchetRevisionConflictException::class.java) {
            repository.commitOutbound(
                missingId,
                1,
                NOW,
                1,
                1,
                OwnedSecret.takeOwnership(outboundState),
                ByteArray(16) { 0x56 },
                "CB1:missing".encodeToByteArray(),
            )
        }
        assertTrue(outboundState.all { it == 0.toByte() })

        val inboundState = ByteArray(64) { 0x57 }
        val inboundPlaintext = "missing-contact-plaintext".encodeToByteArray()
        assertEquals(
            AtomicInboundResult.REVISION_CONFLICT,
            repository.commitInbound(
                missingId,
                1,
                NOW,
                1,
                1,
                OwnedSecret.takeOwnership(inboundState),
                ByteArray(16) { 0x58 },
                ByteArray(32) { 0x59 },
                OwnedSecret.takeOwnership(inboundPlaintext),
            ),
        )
        assertTrue(inboundState.all { it == 0.toByte() })
        assertTrue(inboundPlaintext.all { it == 0.toByte() })
    }

    @Test
    fun corruptSessionCanBeMarkedAsRepairRequired() {
        stagePairing()
        owner(3).use { updated ->
            contact().use { value ->
                assertTrue(
                    repository.completePairing(
                        pairingId, 1, 2, 0, NOW, updated, value, 0, 1, secret("state"),
                    ),
                )
            }
        }

        assertTrue(
            repository.updateContactStatus(
                contactId = contactId,
                expectedRevision = 1,
                verificationStatus = ContactVerificationStatus.SESSION_ERROR,
                requiresRepairing = true,
                sessionError = true,
                keyChanged = false,
                lastActiveAtEpochMillis = NOW + 1,
            ),
        )
        repository.readContact(contactId)!!.use {
            assertEquals(ContactVerificationStatus.SESSION_ERROR, it.value.verificationStatus)
            assertTrue(it.value.requiresRepairing)
            assertTrue(it.value.sessionError)
        }
    }

    @Test
    fun identityReplacementCannotAtomicallyBecomeVerified() {
        stagePairing()
        owner(3).use { updated ->
            contact().use { current ->
                assertTrue(
                    repository.completePairing(
                        pairingId,
                        1,
                        2,
                        0,
                        NOW,
                        updated,
                        current,
                        0,
                        1,
                        secret("old-session"),
                    ),
                )
            }
        }
        assertTrue(repository.destroyContactSession(contactId, 1, 1, NOW))

        val replacementPairingId = ByteArray(16) { (it + 70).toByte() }
        owner(4).use { updated ->
            pending(replacementPairingId).use {
                assertTrue(repository.stagePendingPairing(3, updated, it))
            }
        }
        owner(5).use { updated ->
            replacementContact(ContactVerificationStatus.VERIFIED).use { unsafeReplacement ->
                assertFalse(
                    repository.completePairing(
                        replacementPairingId,
                        1,
                        4,
                        2,
                        NOW,
                        updated,
                        unsafeReplacement,
                        0,
                        1,
                        secret("must-not-commit"),
                        allowIdentityReplacement = true,
                    ),
                )
            }
        }
        assertNull(store.readRatchet(contactId))

        owner(5).use { updated ->
            replacementContact(ContactVerificationStatus.KEY_CHANGED).use { blockedReplacement ->
                assertTrue(
                    repository.completePairing(
                        replacementPairingId,
                        1,
                        4,
                        2,
                        NOW,
                        updated,
                        blockedReplacement,
                        0,
                        1,
                        secret("fresh-session"),
                        allowIdentityReplacement = true,
                    ),
                )
            }
        }
        repository.readContact(contactId)!!.use {
            assertEquals(ContactVerificationStatus.KEY_CHANGED, it.value.verificationStatus)
            assertTrue(it.value.keyChanged)
            assertFalse(it.value.requiresRepairing)
        }
        store.readRatchet(contactId)!!.use {
            it.secret.consume { state -> assertArrayEquals("fresh-session".encodeToByteArray(), state) }
        }
        replacementPairingId.wipe()
    }

    @Test
    fun completionRejectsIdentityOrRoutingTagOwnedByAnotherContact() {
        stagePairing()
        val firstFingerprint = ByteArray(32) { (it + 4).toByte() }
        owner(3).use { updated ->
            contact().use { first ->
                assertTrue(repository.completePairing(pairingId, 1, 2, 0, NOW, updated, first, 0, 1, secret("first")))
            }
        }

        val secondPairingId = ByteArray(16) { (it + 80).toByte() }
        val secondContactId = ByteArray(16) { (it + 100).toByte() }
        owner(4).use { updated ->
            pending(secondPairingId).use { assertTrue(repository.stagePendingPairing(3, updated, it)) }
        }
        owner(5).use { updated ->
            contact(
                localName = "Duplicate identity",
                internalId = secondContactId,
                remoteFingerprint = firstFingerprint,
                remoteTag = ByteArray(16) { (it + 33).toByte() },
            ).use { duplicate ->
                assertFalse(
                    repository.completePairing(
                        secondPairingId, 1, 4, 0, NOW, updated, duplicate, 0, 1, secret("duplicate"),
                    ),
                )
            }
        }
        assertNull(repository.readContact(secondContactId))
        repository.readPendingPairing(secondPairingId)!!.use {
            assertEquals(OneShotStatus.ACTIVE, it.value.oneShotStatus)
        }
        firstFingerprint.wipe()
        secondPairingId.wipe()
        secondContactId.wipe()
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

    private fun pending(
        id: ByteArray = pairingId,
        createdAtEpochMillis: Long = NOW,
    ) = PendingPairingState(
        type = PendingPairingType.OFFER,
        pairingId = id,
        createdAtEpochMillis = createdAtEpochMillis,
        expiresAtEpochMillis = createdAtEpochMillis + 300_000,
        nonce = ByteArray(32) { (it + 1).toByte() },
        transcriptHash = ByteArray(32) { (it + 2).toByte() },
        oneShotStatus = OneShotStatus.ACTIVE,
        protocolVersion = 1,
        payload = ByteArray(96) { (it + 3).toByte() },
    )

    private fun contact(
        localName: String = "Боб 🔐",
        internalId: ByteArray = contactId,
        remoteFingerprint: ByteArray = ByteArray(32) { (it + 4).toByte() },
        remoteTag: ByteArray = ByteArray(16) { (it + 5).toByte() },
    ) = ContactVaultEntry(
        internalId = internalId,
        localName = localName,
        remoteIdentityFingerprint = remoteFingerprint,
        remoteSessionTag = remoteTag,
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

    private fun replacementContact(status: ContactVerificationStatus) = ContactVaultEntry(
        internalId = contactId,
        localName = "Боб 🔐",
        remoteIdentityFingerprint = ByteArray(32) { (it + 90).toByte() },
        remoteSessionTag = ByteArray(16) { (it + 91).toByte() },
        verificationStatus = status,
        pairedAtEpochMillis = NOW,
        lastActiveAtEpochMillis = NOW,
        protocolVersion = 1,
        safetyNumber = "98765 43210 98765 43210",
        safetyCode = "delta cedar beacon amber",
        requiresRepairing = false,
        sessionError = false,
        keyChanged = status == ContactVerificationStatus.KEY_CHANGED,
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
