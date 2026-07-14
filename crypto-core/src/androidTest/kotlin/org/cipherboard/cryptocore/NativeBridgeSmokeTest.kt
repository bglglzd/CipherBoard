package org.cipherboard.cryptocore

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeBridgeSmokeTest {
    @Test
    fun nativeSymbolAndAliceBobRoundTrip() {
        val crypto = CipherBoardCrypto()
        assertEquals(ProtocolVersions(cipherBoard = 1, olmSession = 2), crypto.protocolVersions())

        val aliceCreated = crypto.createAccount()
        val bobCreated = crypto.createAccount()
        var aliceAccount = aliceCreated.accountState
        val bobAccount = bobCreated.accountState
        var aliceSession: OwnedSecret? = null
        var bobSession: OwnedSecret? = null
        try {
            assertTrue(aliceCreated.fingerprint.size == 32)
            assertTrue(bobCreated.fingerprint.size == 32)

            val offer = crypto.createOffer(
                accountState = aliceAccount,
                nowEpochSeconds = NOW,
                ttlSeconds = 600,
                capabilities = CAPABILITIES,
            )
            aliceAccount.clear()
            aliceAccount = offer.accountState
            assertTrue(offer.offerQr.decodeToString().startsWith("CBO1:"))
            val offerMetadata = crypto.parsePairingPayload(offer.offerQr, NOW + 1)
            assertEquals(PairingPayloadType.OFFER, offerMetadata.type)
            assertEquals(PairingPayloadStatus.VALID, offerMetadata.status)
            assertEquals(NOW + 600, offerMetadata.expiresAtEpochSeconds)
            assertEquals(CAPABILITIES, offerMetadata.capabilities)
            assertArrayEquals(aliceCreated.fingerprint, offerMetadata.remoteIdentityFingerprint)
            assertArrayEquals(aliceCreated.identity.curve25519, offerMetadata.remoteIdentity.curve25519)
            assertEquals(
                PairingPayloadStatus.EXPIRED,
                crypto.parsePairingPayload(offer.offerQr, NOW + 601).status,
            )

            val response = crypto.respondToOffer(
                accountState = bobAccount,
                offerQr = offer.offerQr,
                nowEpochSeconds = NOW + 1,
                capabilities = CAPABILITIES,
            )
            bobSession = response.sessionState
            assertTrue(response.responseQr.decodeToString().startsWith("CBR1:"))
            assertArrayEquals(offerMetadata.remoteIdentityFingerprint, response.remoteIdentityFingerprint)
            val responseMetadata = crypto.parsePairingPayload(response.responseQr, NOW + 2)
            assertEquals(PairingPayloadType.RESPONSE, responseMetadata.type)
            assertEquals(PairingPayloadStatus.VALID, responseMetadata.status)
            assertEquals(null, responseMetadata.expiresAtEpochSeconds)
            assertArrayEquals(offerMetadata.pairingId, responseMetadata.pairingId)
            assertArrayEquals(offerMetadata.offerHash, responseMetadata.offerHash)
            assertArrayEquals(bobCreated.fingerprint, responseMetadata.remoteIdentityFingerprint)

            val completed = crypto.completePairing(
                accountState = aliceAccount,
                offerQr = offer.offerQr,
                responseQr = response.responseQr,
                nowEpochSeconds = NOW + 2,
            )
            aliceAccount.clear()
            aliceAccount = completed.accountState
            aliceSession = completed.sessionState
            assertArrayEquals(response.safetyCode.hash, completed.safetyCode.hash)
            assertArrayEquals(response.routingTag, completed.routingTag)
            assertArrayEquals(responseMetadata.remoteIdentityFingerprint, completed.remoteIdentityFingerprint)

            val plaintext = OwnedSecret.takeOwnership("JNI smoke: Привет 👋".encodeToByteArray())
            val encrypted = try {
                crypto.encrypt(
                    sessionState = aliceSession,
                    plaintext = plaintext,
                    capabilities = CAPABILITIES,
                    mode = TransportMode.UNIVERSAL,
                )
            } finally {
                plaintext.clear()
            }
            aliceSession.clear()
            aliceSession = encrypted.sessionState

            for (presentation in TransportPresentation.entries) {
                val presented = crypto.encodePresentation(encrypted.parts, presentation)
                if (presentation != TransportPresentation.COMPACT) {
                    assertTrue(!presented.startsWith("CB1:"))
                    assertTrue(presented.contains(' '))
                }
                val decoded = crypto.decodePresentation(presented)
                assertEquals(presentation, decoded.presentation)
                assertEquals(encrypted.parts, decoded.parts)
            }

            val decrypted = crypto.decrypt(bobSession, encrypted.parts)
            bobSession.clear()
            bobSession = decrypted.sessionState
            decrypted.plaintext.use {
                assertArrayEquals("JNI smoke: Привет 👋".encodeToByteArray(), it)
            }
            decrypted.plaintext.clear()
        } finally {
            aliceAccount.clear()
            bobAccount.clear()
            aliceSession?.clear()
            bobSession?.clear()
        }
    }

    private companion object {
        const val NOW = 1_800_000_000L
        const val CAPABILITIES = 7L
    }
}
