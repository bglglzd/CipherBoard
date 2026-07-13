// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingPairingPayloadCodecTest {
    @Test
    fun responderPayloadRoundTripsWithoutObjectSerialization() {
        val source = PendingPairingPayload(
            role = PendingPairingRole.RESPONDER,
            replacingExistingContact = true,
            requestedCapabilities = 0xfedc_ba98L,
            contactId = ByteArray(16) { it.toByte() },
            localContactName = "Алиса",
            offerQr = "CBO1:offer".encodeToByteArray(),
            responseQr = "CBR1:response".encodeToByteArray(),
            sessionState = ByteArray(1024) { (it and 0xff).toByte() },
            remoteFingerprint = ByteArray(32) { 3 },
            routingTag = ByteArray(16) { 4 },
            safetyNumber = "1234 5678",
            safetyCode = "amber cedar",
        )
        source.use {
            val encoded = PendingPairingPayloadCodec.encode(it)
            try {
                PendingPairingPayloadCodec.decode(encoded).use { decoded ->
                    assertEquals(PendingPairingRole.RESPONDER, decoded.role)
                    assertTrue(decoded.replacingExistingContact)
                    assertEquals(0xfedc_ba98L, decoded.requestedCapabilities)
                    assertEquals("Алиса", decoded.localContactName)
                    assertArrayEquals(it.contactId, decoded.contactId)
                    assertArrayEquals(it.sessionState, decoded.sessionState)
                    assertEquals("1234 5678", decoded.safetyNumber)
                    assertEquals("amber cedar", decoded.safetyCode)
                }
            } finally {
                encoded.fill(0)
            }
        }
    }

    @Test
    fun offererPayloadRejectsSecretSessionMaterial() {
        assertThrows(IllegalArgumentException::class.java) {
            PendingPairingPayload(
                role = PendingPairingRole.OFFERER,
                replacingExistingContact = false,
                requestedCapabilities = 0,
                contactId = ByteArray(16),
                localContactName = "Bob",
                offerQr = "CBO1:offer".encodeToByteArray(),
                responseQr = ByteArray(0),
                sessionState = byteArrayOf(1),
                remoteFingerprint = ByteArray(0),
                routingTag = ByteArray(0),
                safetyNumber = "",
                safetyCode = "",
            )
        }
    }

    @Test
    fun decoderRejectsTruncationTrailingBytesAndInvalidFlags() {
        val source = offerPayload()
        source.use {
            val encoded = PendingPairingPayloadCodec.encode(it)
            try {
                assertThrows(IllegalArgumentException::class.java) {
                    PendingPairingPayloadCodec.decode(encoded.copyOf(encoded.size - 1))
                }
                assertThrows(IllegalArgumentException::class.java) {
                    PendingPairingPayloadCodec.decode(encoded + byteArrayOf(0))
                }
                val invalidFlags = encoded.copyOf().also { bytes -> bytes[6] = 2 }
                try {
                    assertThrows(IllegalArgumentException::class.java) {
                        PendingPairingPayloadCodec.decode(invalidFlags)
                    }
                } finally {
                    invalidFlags.fill(0)
                }
            } finally {
                encoded.fill(0)
            }
        }
    }

    @Test
    fun closeOverwritesOwnedBinaryCopies() {
        val payload = offerPayload()
        payload.close()
        assertTrue(payload.contactId.all { it == 0.toByte() })
        assertTrue(payload.offerQr.all { it == 0.toByte() })
        assertFalse(payload.replacingExistingContact)
    }

    private fun offerPayload() = PendingPairingPayload(
        role = PendingPairingRole.OFFERER,
        replacingExistingContact = false,
        requestedCapabilities = 7,
        contactId = ByteArray(16) { 7 },
        localContactName = "Bob",
        offerQr = "CBO1:offer".encodeToByteArray(),
        responseQr = ByteArray(0),
        sessionState = ByteArray(0),
        remoteFingerprint = ByteArray(0),
        routingTag = ByteArray(0),
        safetyNumber = "",
        safetyCode = "",
    )
}
