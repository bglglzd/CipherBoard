package org.cipherboard.pairing

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DuplicateDebouncerTest {
    @Test
    fun suppressesOnlySamePayloadInsideWindow() {
        val debouncer = DuplicateDebouncer(1_500)
        val first = PairingQrPayload.parse("CBO1:first")
        val second = PairingQrPayload.parse("CBO1:second")

        assertTrue(debouncer.shouldDeliver(first, 1_000))
        assertFalse(debouncer.shouldDeliver(first, 2_499))
        assertTrue(debouncer.shouldDeliver(second, 2_499))
        assertTrue(debouncer.shouldDeliver(first, 2_500))
        debouncer.close()
        assertTrue(debouncer.shouldDeliver(first, 2_501))
    }

    @Test
    fun monotonicClockRollbackDoesNotSuppressIndefinitely() {
        val debouncer = DuplicateDebouncer(1_500)
        val payload = PairingQrPayload.parse("CBR1:response")
        assertTrue(debouncer.shouldDeliver(payload, 10_000))
        assertTrue(debouncer.shouldDeliver(payload, 5_000))
    }
}
