package org.cipherboard.cryptocore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PairingMetadataModelTest {
    @Test
    fun offerAndResponseExpirySemanticsAreExplicit() {
        val identity = PublicIdentity(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val offer = PairingPayloadMetadata(
            type = PairingPayloadType.OFFER,
            pairingId = ByteArray(16),
            remoteIdentity = identity,
            remoteIdentityFingerprint = ByteArray(32),
            nonce = ByteArray(32),
            capabilities = 7,
            expiresAtEpochSeconds = 1_800_000_600,
            status = PairingPayloadStatus.EXPIRED,
            offerHash = ByteArray(32),
        )
        assertEquals(PairingPayloadStatus.EXPIRED, offer.status)

        val response = PairingPayloadMetadata(
            type = PairingPayloadType.RESPONSE,
            pairingId = ByteArray(16),
            remoteIdentity = identity,
            remoteIdentityFingerprint = ByteArray(32),
            nonce = ByteArray(32),
            capabilities = 7,
            expiresAtEpochSeconds = null,
            status = PairingPayloadStatus.VALID,
            offerHash = ByteArray(32),
        )
        assertEquals(null, response.expiresAtEpochSeconds)
    }

    @Test
    fun responseCannotClaimOfferExpiry() {
        assertFailsWith<IllegalArgumentException> {
            PairingPayloadMetadata(
                type = PairingPayloadType.RESPONSE,
                pairingId = ByteArray(16),
                remoteIdentity = PublicIdentity(ByteArray(32), ByteArray(32)),
                remoteIdentityFingerprint = ByteArray(32),
                nonce = ByteArray(32),
                capabilities = 0,
                expiresAtEpochSeconds = 42,
                status = PairingPayloadStatus.EXPIRED,
                offerHash = ByteArray(32),
            )
        }
    }

    @Test
    fun stableErrorsLetUiSeparateInvalidExpiredAndReused() {
        assertEquals(CryptoErrorCode.INVALID_SIGNATURE, CryptoCoreException(8).reason)
        assertEquals(CryptoErrorCode.EXPIRED_OFFER, CryptoCoreException(9).reason)
        assertEquals(CryptoErrorCode.PAIRING_ALREADY_USED, CryptoCoreException(11).reason)
        assertEquals(CryptoErrorCode.UNKNOWN, CryptoCoreException(999).reason)
    }
}
