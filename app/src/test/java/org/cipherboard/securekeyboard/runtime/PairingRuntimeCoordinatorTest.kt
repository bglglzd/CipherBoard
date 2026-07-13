// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.OfferCreated
import org.cipherboard.cryptocore.OwnedSecret as CryptoOwnedSecret
import org.cipherboard.cryptocore.PairingCompleted
import org.cipherboard.cryptocore.PairingPayloadMetadata
import org.cipherboard.cryptocore.PairingPayloadStatus
import org.cipherboard.cryptocore.PairingPayloadType
import org.cipherboard.cryptocore.PairingResponseCreated
import org.cipherboard.cryptocore.PublicIdentity
import org.cipherboard.cryptocore.SafetyCode
import org.cipherboard.pairing.PairingQrPayload
import org.cipherboard.securestorage.ContactVaultEntry
import org.cipherboard.securestorage.ContactVerificationStatus
import org.cipherboard.securestorage.OneShotStatus
import org.cipherboard.securestorage.OwnerIdentityAccountState
import org.cipherboard.securestorage.OwnedSecret as StorageOwnedSecret
import org.cipherboard.securestorage.PendingPairingState
import org.cipherboard.securestorage.VersionedDomainRecord
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingRuntimeCoordinatorTest {
    @Test
    fun offererStagesOfferThenAtomicallyConsumesItWithInitialRatchet() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        val offer = fixture.coordinator.createOffer("Bob", 300, 5)
        offer.use {
            assertEquals("CBO1:offer", it.qrPayload.value)
            assertEquals(NOW_MILLIS + 300_000, it.expiresAtEpochMillis)
        }
        PendingPairingPayloadCodec.decode(fixture.vault.pending!!.payload).use { payload ->
            assertEquals(PendingPairingRole.OFFERER, payload.role)
            assertTrue(payload.sessionState.isEmpty())
        }

        val prepared = fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        assertEquals(SAFETY_NUMBER, prepared.safetyNumber)
        val contact = fixture.coordinator.confirm(prepared)

        assertEquals(ContactVerificationStatus.VERIFIED, contact.verificationStatus)
        assertEquals("Bob", contact.localName)
        assertArrayEquals(SESSION_A, fixture.vault.ratchet)
        assertEquals(OneShotStatus.CONSUMED, fixture.vault.pending!!.oneShotStatus)
        val replay = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        }
        assertEquals(PairingRuntimeError.ALREADY_USED, replay.reason)
    }

    @Test
    fun responderPersistsSessionAndCanResumeSameResponseBeforeConfirmation() {
        val fixture = Fixture(localFingerprint = BOB_FINGERPRINT)
        val offer = PairingQrPayload.parse("CBO1:offer")
        val first = fixture.coordinator.respondToOffer("Alice", offer, 5)
        val resumed = fixture.coordinator.respondToOffer("Alice", offer, 5)
        assertEquals(1, fixture.crypto.respondCalls)
        assertEquals(first.qrPayload, resumed.qrPayload)
        first.close()

        val contact = fixture.coordinator.confirm(resumed)
        assertEquals("Alice", contact.localName)
        assertArrayEquals(SESSION_B, fixture.vault.ratchet)
        assertEquals(OneShotStatus.CONSUMED, fixture.vault.pending!!.oneShotStatus)
    }

    @Test
    fun responderResumeRejectsDifferentLocalNameWithoutCallingCryptoAgain() {
        val fixture = Fixture(localFingerprint = BOB_FINGERPRINT)
        val offer = PairingQrPayload.parse("CBO1:offer")
        fixture.coordinator.respondToOffer("Alice", offer, 5).close()

        val error = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.respondToOffer("Mallory", offer, 5)
        }
        assertEquals(PairingRuntimeError.ALREADY_USED, error.reason)
        assertEquals(1, fixture.crypto.respondCalls)
    }

    @Test
    fun responderResumeRejectsDifferentCapabilitiesWithoutCallingCryptoAgain() {
        val fixture = Fixture(localFingerprint = BOB_FINGERPRINT)
        val offer = PairingQrPayload.parse("CBO1:offer")
        fixture.coordinator.respondToOffer("Alice", offer, 5).close()

        val error = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.respondToOffer("Alice", offer, 6)
        }
        assertEquals(PairingRuntimeError.ALREADY_USED, error.reason)
        assertEquals(1, fixture.crypto.respondCalls)
    }

    @Test
    fun responderResumeRejectsDifferentReplacementContactWithoutCallingCryptoAgain() {
        val fixture = Fixture(localFingerprint = BOB_FINGERPRINT)
        val offer = PairingQrPayload.parse("CBO1:offer")
        val existingId = ByteArray(16) { 42 }
        val otherId = ByteArray(16) { 43 }
        fixture.vault.contact = repairingContact(existingId)
        fixture.coordinator.respondToOffer("Bob", offer, 5, existingId).close()

        val error = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.respondToOffer("Bob", offer, 5, otherId)
        }
        assertEquals(PairingRuntimeError.ALREADY_USED, error.reason)
        assertEquals(1, fixture.crypto.respondCalls)
        existingId.fill(0)
        otherId.fill(0)
    }

    @Test
    fun responderRepairWithChangedIdentityStaysBlockedUntilSeparateVerification() {
        val fixture = Fixture(localFingerprint = BOB_FINGERPRINT)
        val offer = PairingQrPayload.parse("CBO1:offer")
        val existingId = ByteArray(16) { 42 }
        fixture.vault.contact = repairingContact(existingId)

        val response = fixture.coordinator.respondToOffer("Bob", offer, 5, existingId)
        assertTrue(response.identityChanged)
        val replacement = fixture.coordinator.confirm(response)

        assertEquals(ContactVerificationStatus.KEY_CHANGED, replacement.verificationStatus)
        assertTrue(replacement.keyChanged)
        assertTrue(!replacement.requiresRepairing)
        assertArrayEquals(SESSION_B, fixture.vault.ratchet)
        existingId.fill(0)
    }

    @Test
    fun expiredPendingOfferIsMarkedExpiredAndCannotComplete() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        fixture.coordinator.createOffer("Bob", 30, 0).close()
        fixture.clock.currentMillis = NOW_MILLIS + 301_000

        val error = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        }
        assertEquals(PairingRuntimeError.EXPIRED, error.reason)
        assertEquals(OneShotStatus.EXPIRED, fixture.vault.pending!!.oneShotStatus)
    }

    @Test
    fun entryCleanupCancelsActiveOfferAndKeepsOnlyReplayTombstone() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        fixture.coordinator.createOffer("Bob", 300, 0).close()

        assertEquals(1, fixture.coordinator.cancelActivePairings())
        assertEquals(OneShotStatus.CANCELLED, fixture.vault.pending!!.oneShotStatus)
        assertArrayEquals(byteArrayOf(0), fixture.vault.pending!!.payload)
        assertEquals(0, fixture.coordinator.cancelActivePairings())

        val replay = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        }
        assertEquals(PairingRuntimeError.ALREADY_USED, replay.reason)
    }

    @Test
    fun entryCleanupExpiresStaleOfferAndKeepsOnlyReplayTombstone() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        fixture.coordinator.createOffer("Bob", 30, 0).close()
        fixture.clock.currentMillis = NOW_MILLIS + 301_000

        assertEquals(1, fixture.coordinator.cancelActivePairings())
        assertEquals(OneShotStatus.EXPIRED, fixture.vault.pending!!.oneShotStatus)
        assertArrayEquals(byteArrayOf(0), fixture.vault.pending!!.payload)
    }

    @Test
    fun cancelledResponderRecordRejectsReuseOfTheSameOffer() {
        val fixture = Fixture(localFingerprint = BOB_FINGERPRINT)
        val offer = PairingQrPayload.parse("CBO1:offer")
        fixture.coordinator.respondToOffer("Alice", offer, 0).close()
        assertEquals(1, fixture.coordinator.cancelActivePairings())

        val replay = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.respondToOffer("Alice", offer, 0)
        }
        assertEquals(PairingRuntimeError.ALREADY_USED, replay.reason)
        assertEquals(1, fixture.crypto.respondCalls)
    }

    @Test
    fun rePairingWithChangedIdentityCommitsBlockedKeyChangedContact() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        val existingId = ByteArray(16) { 42 }
        fixture.vault.contact = repairingContact(existingId)

        fixture.coordinator.createOffer("Bob", 300, 0, existingId).close()
        val prepared = fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        assertTrue(prepared.identityChanged)
        val previousFingerprint = prepared.previousRemoteFingerprint()
        try {
            assertArrayEquals(ByteArray(32) { 99 }, previousFingerprint)
        } finally {
            previousFingerprint.fill(0)
        }
        val replacement = fixture.coordinator.confirm(prepared)

        assertArrayEquals(existingId, replacement.internalId())
        assertEquals(1L, fixture.vault.completedContactRevision)
        assertTrue(fixture.vault.allowedIdentityReplacement)
        assertEquals(ContactVerificationStatus.KEY_CHANGED, replacement.verificationStatus)
        assertTrue(replacement.keyChanged)
        assertTrue(!replacement.requiresRepairing)
        existingId.fill(0)
    }

    @Test
    fun rePairingWithUnchangedIdentityCanRemainVerified() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        val existingId = ByteArray(16) { 42 }
        fixture.vault.contact = repairingContact(existingId, BOB_FINGERPRINT)

        fixture.coordinator.createOffer("Bob", 300, 0, existingId).close()
        val prepared = fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        assertTrue(!prepared.identityChanged)
        val replacement = fixture.coordinator.confirm(prepared)

        assertEquals(ContactVerificationStatus.VERIFIED, replacement.verificationStatus)
        assertTrue(!replacement.keyChanged)
        existingId.fill(0)
    }

    @Test
    fun newPairingRejectsRemoteIdentityAlreadyStoredUnderAnotherContact() {
        val fixture = Fixture(localFingerprint = ALICE_FINGERPRINT)
        val existingId = ByteArray(16) { 42 }
        fixture.vault.contact = repairingContact(existingId, BOB_FINGERPRINT)

        fixture.coordinator.createOffer("Duplicate Bob", 300, 0).close()
        val prepared = fixture.coordinator.prepareResponse(PairingQrPayload.parse("CBR1:response"))
        val error = assertThrows(PairingRuntimeException::class.java) {
            fixture.coordinator.confirm(prepared)
        }

        assertEquals(PairingRuntimeError.CONTACT_ALREADY_EXISTS, error.reason)
        assertEquals(OneShotStatus.ACTIVE, fixture.vault.pending!!.oneShotStatus)
        existingId.fill(0)
    }

    private class Fixture(localFingerprint: ByteArray) {
        val clock = MutableClock(NOW_MILLIS)
        val crypto = FakeCrypto(localFingerprint)
        val vault = FakeVault(owner(localFingerprint))
        private var randomCounter = 1
        val coordinator = PairingRuntimeCoordinator(crypto, vault, clock) { destination ->
            destination.fill((randomCounter++).toByte())
        }
    }

    private class FakeCrypto(
        private val localFingerprint: ByteArray,
    ) : PairingCryptoOperations {
        var respondCalls = 0

        override fun createOffer(
            accountState: CryptoOwnedSecret,
            nowEpochSeconds: Long,
            ttlSeconds: Long,
            capabilities: Long,
        ) = OfferCreated(CryptoOwnedSecret.takeOwnership(byteArrayOf(2)), OFFER.copyOf())

        override fun respondToOffer(
            accountState: CryptoOwnedSecret,
            offerQr: ByteArray,
            nowEpochSeconds: Long,
            capabilities: Long,
        ): PairingResponseCreated {
            respondCalls++
            return PairingResponseCreated(
                CryptoOwnedSecret.takeOwnership(SESSION_B.copyOf()),
                RESPONSE.copyOf(),
                safety(),
                identity(ALICE_FINGERPRINT),
                ROUTING_TAG.copyOf(),
                ALICE_FINGERPRINT.copyOf(),
            )
        }

        override fun completePairing(
            accountState: CryptoOwnedSecret,
            offerQr: ByteArray,
            responseQr: ByteArray,
            nowEpochSeconds: Long,
        ) = PairingCompleted(
            CryptoOwnedSecret.takeOwnership(byteArrayOf(3)),
            CryptoOwnedSecret.takeOwnership(SESSION_A.copyOf()),
            safety(),
            identity(BOB_FINGERPRINT),
            ROUTING_TAG.copyOf(),
            BOB_FINGERPRINT.copyOf(),
        )

        override fun parsePairingPayload(
            qrPayload: ByteArray,
            nowEpochSeconds: Long,
        ): PairingPayloadMetadata = when {
            qrPayload.contentEquals(OFFER) -> PairingPayloadMetadata(
                PairingPayloadType.OFFER,
                PAIRING_ID.copyOf(),
                identity(ALICE_FINGERPRINT),
                ALICE_FINGERPRINT.copyOf(),
                NONCE.copyOf(),
                5,
                NOW_SECONDS + 300,
                if (nowEpochSeconds > NOW_SECONDS + 300) {
                    PairingPayloadStatus.EXPIRED
                } else {
                    PairingPayloadStatus.VALID
                },
                OFFER_HASH.copyOf(),
            )
            qrPayload.contentEquals(RESPONSE) -> PairingPayloadMetadata(
                PairingPayloadType.RESPONSE,
                PAIRING_ID.copyOf(),
                identity(BOB_FINGERPRINT),
                BOB_FINGERPRINT.copyOf(),
                RESPONSE_NONCE.copyOf(),
                5,
                null,
                PairingPayloadStatus.VALID,
                OFFER_HASH.copyOf(),
            )
            else -> throw IllegalArgumentException("invalid test QR")
        }

        private fun safety() = SafetyCode(SAFETY_HASH.copyOf(), SAFETY_NUMBER, SAFETY_CODE)
    }

    private class FakeVault(initialOwner: OwnerIdentityAccountState) : PairingVaultOperations {
        private var owner = initialOwner
        private var ownerRevision = 1L
        var pending: PendingPairingState? = null
        private var pendingRevision = 0L
        var contact: ContactVaultEntry? = null
        var ratchet: ByteArray? = null
        var completedContactRevision = -1L
        var allowedIdentityReplacement = false

        override fun readOwner() = VersionedDomainRecord(ownerRevision, copyOwner(owner))

        override fun readPending(pairingId: ByteArray): VersionedDomainRecord<PendingPairingState>? {
            val value = pending ?: return null
            if (!value.pairingId.contentEquals(pairingId)) return null
            return VersionedDomainRecord(pendingRevision, copyPending(value))
        }

        override fun readContact(contactId: ByteArray): VersionedDomainRecord<ContactVaultEntry>? {
            val value = contact ?: return null
            if (!value.internalId.contentEquals(contactId)) return null
            return VersionedDomainRecord(1, copyContact(value))
        }

        override fun listContacts(): List<VersionedDomainRecord<ContactVaultEntry>> {
            val value = contact ?: return emptyList()
            return listOf(VersionedDomainRecord(1, copyContact(value)))
        }

        override fun listActivePending(
            limit: Int,
        ): List<VersionedDomainRecord<PendingPairingState>> {
            require(limit > 0)
            val value = pending ?: return emptyList()
            if (value.oneShotStatus != OneShotStatus.ACTIVE) return emptyList()
            return listOf(VersionedDomainRecord(pendingRevision, copyPending(value)))
        }

        override fun stage(
            expectedOwnerRevision: Long,
            updatedOwner: OwnerIdentityAccountState,
            pending: PendingPairingState,
        ): Boolean {
            if (expectedOwnerRevision != ownerRevision || this.pending != null) return false
            owner.close()
            owner = copyOwner(updatedOwner)
            ownerRevision++
            this.pending = copyPending(pending)
            pendingRevision = 1
            return true
        }

        override fun complete(
            pairingId: ByteArray,
            expectedPairingRevision: Long,
            expectedOwnerRevision: Long,
            expectedContactRevision: Long,
            nowEpochMillis: Long,
            updatedOwner: OwnerIdentityAccountState,
            contact: ContactVaultEntry,
            initialRatchetState: StorageOwnedSecret,
            allowIdentityReplacement: Boolean,
        ): Boolean {
            val current = pending ?: return false
            if (current.oneShotStatus != OneShotStatus.ACTIVE ||
                expectedPairingRevision != pendingRevision || expectedOwnerRevision != ownerRevision ||
                nowEpochMillis > current.expiresAtEpochMillis
            ) return false
            completedContactRevision = expectedContactRevision
            allowedIdentityReplacement = allowIdentityReplacement
            ratchet = initialRatchetState.consume { it.copyOf() }
            owner.close()
            owner = copyOwner(updatedOwner)
            ownerRevision++
            this.contact?.close()
            this.contact = copyContact(contact)
            val consumed = copyPendingWithStatus(current, OneShotStatus.CONSUMED)
            current.close()
            pending = consumed
            pendingRevision++
            return true
        }

        override fun cancel(pairingId: ByteArray, expectedRevision: Long): Boolean =
            transition(pairingId, expectedRevision, OneShotStatus.CANCELLED)

        override fun expire(
            pairingId: ByteArray,
            expectedRevision: Long,
            nowEpochMillis: Long,
        ): Boolean = transition(pairingId, expectedRevision, OneShotStatus.EXPIRED)

        private fun transition(pairingId: ByteArray, revision: Long, status: OneShotStatus): Boolean {
            val current = pending ?: return false
            if (revision != pendingRevision || !current.pairingId.contentEquals(pairingId)) return false
            val changed = copyPendingWithStatus(current, status)
            current.close()
            pending = changed
            pendingRevision++
            return true
        }
    }

    private class MutableClock(var currentMillis: Long) : EpochMillisSource {
        override fun nowEpochMillis(): Long = currentMillis
    }

    companion object {
        private const val NOW_SECONDS = 1_800_000_000L
        private const val NOW_MILLIS = NOW_SECONDS * 1_000
        private val OFFER = "CBO1:offer".encodeToByteArray()
        private val RESPONSE = "CBR1:response".encodeToByteArray()
        private val PAIRING_ID = ByteArray(16) { 7 }
        private val NONCE = ByteArray(32) { 8 }
        private val RESPONSE_NONCE = ByteArray(32) { 6 }
        private val OFFER_HASH = ByteArray(32) { 9 }
        private val SAFETY_HASH = ByteArray(32) { 10 }
        private val ROUTING_TAG = ByteArray(16) { 11 }
        private val ALICE_FINGERPRINT = ByteArray(32) { 12 }
        private val BOB_FINGERPRINT = ByteArray(32) { 13 }
        private val SESSION_A = byteArrayOf(21, 22, 23)
        private val SESSION_B = byteArrayOf(31, 32, 33)
        private const val SAFETY_NUMBER = "1234 5678"
        private const val SAFETY_CODE = "amber cedar"

        private fun identity(seed: ByteArray) = PublicIdentity(seed.copyOf(), seed.copyOf())

        private fun owner(fingerprint: ByteArray) = OwnerIdentityAccountState(
            "Owner",
            byteArrayOf(1),
            fingerprint,
            1,
            NOW_MILLIS,
        )

        private fun copyOwner(value: OwnerIdentityAccountState) = OwnerIdentityAccountState(
            value.localOwnerName,
            value.accountState,
            value.identityFingerprint,
            value.protocolVersion,
            value.createdAtEpochMillis,
        )

        private fun copyPending(value: PendingPairingState) = copyPendingWithStatus(
            value,
            value.oneShotStatus,
        )

        private fun copyPendingWithStatus(value: PendingPairingState, status: OneShotStatus) =
            PendingPairingState(
                value.type,
                value.pairingId,
                value.createdAtEpochMillis,
                value.expiresAtEpochMillis,
                value.nonce,
                value.transcriptHash,
                status,
                value.protocolVersion,
                if (status == OneShotStatus.ACTIVE) value.payload else byteArrayOf(0),
            )

        private fun copyContact(value: ContactVaultEntry) = ContactVaultEntry(
            value.internalId,
            value.localName,
            value.remoteIdentityFingerprint,
            value.remoteSessionTag,
            value.verificationStatus,
            value.pairedAtEpochMillis,
            value.lastActiveAtEpochMillis,
            value.protocolVersion,
            value.safetyNumber,
            value.safetyCode,
            value.requiresRepairing,
            value.sessionError,
            value.keyChanged,
        )

        private fun repairingContact(
            id: ByteArray,
            fingerprint: ByteArray = ByteArray(32) { 99 },
        ) = ContactVaultEntry(
            id,
            "Bob",
            fingerprint,
            ByteArray(16) { 98 },
            ContactVerificationStatus.PAIRING_REQUIRED,
            NOW_MILLIS - 1_000,
            NOW_MILLIS,
            1,
            SAFETY_NUMBER,
            SAFETY_CODE,
            true,
            false,
            false,
        )
    }
}
