package org.cipherboard.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PairingQrPayloadTest {
    @Test
    fun acceptsOnlyVersionedPrintableAsciiPayloads() {
        assertEquals(PairingQrPayloadType.OFFER, PairingQrPayload.parse("CBO1:abc_123-").type)
        assertEquals(PairingQrPayloadType.RESPONSE, PairingQrPayload.parse("CBR1:a:b.c~").type)

        assertReason(PairingQrValidationError.EMPTY, "")
        assertReason(PairingQrValidationError.EMPTY_BODY, "CBO1:")
        assertReason(PairingQrValidationError.UNSUPPORTED_PREFIX, "CBP1:legacy-offer")
        assertReason(PairingQrValidationError.UNSUPPORTED_PREFIX, "CBX1:abc")
        assertReason(PairingQrValidationError.NON_ASCII, "CBO1:привет")
        assertReason(PairingQrValidationError.NON_ASCII, "CBO1:line\nbreak")
        assertNull(PairingQrPayload.parseOrNull(null))
    }

    @Test
    fun enforcesDecodedByteLimitBeforeAllocationHeavyWork() {
        val exact = PairingQrPayload.OFFER_PREFIX +
            "a".repeat(PairingQrPayload.MAX_DECODED_BYTES - PairingQrPayload.OFFER_PREFIX.length)
        assertEquals(PairingQrPayload.MAX_DECODED_BYTES, PairingQrPayload.parse(exact).sizeBytes)

        assertReason(PairingQrValidationError.TOO_LARGE, exact + "a")
    }

    @Test
    fun genericStringRepresentationDoesNotContainPayload() {
        val payload = PairingQrPayload.parse("CBO1:sensitive-public-key-material")
        assertFalse(payload.toString().contains("sensitive-public-key-material"))
    }

    private fun assertReason(expected: PairingQrValidationError, raw: String) {
        val error = assertThrows(PairingQrPayloadException::class.java) {
            PairingQrPayload.parse(raw)
        }
        assertEquals(expected, error.reason)
    }
}
