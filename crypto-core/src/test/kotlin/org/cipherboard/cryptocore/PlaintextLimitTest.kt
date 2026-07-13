package org.cipherboard.cryptocore

import kotlin.test.Test
import kotlin.test.assertFailsWith

class PlaintextLimitTest {
    @Test
    fun oversizedPlaintextIsRejectedBeforeNativeRequestAllocation() {
        val state = OwnedSecret.takeOwnership(byteArrayOf(1))
        val plaintext = OwnedSecret.takeOwnership(ByteArray(CipherBoardCrypto.MAX_PLAINTEXT_BYTES + 1))
        try {
            assertFailsWith<IllegalArgumentException> {
                CipherBoardCrypto().encrypt(state, plaintext, 0, TransportMode.UNIVERSAL)
            }
        } finally {
            state.close()
            plaintext.close()
        }
    }
}
