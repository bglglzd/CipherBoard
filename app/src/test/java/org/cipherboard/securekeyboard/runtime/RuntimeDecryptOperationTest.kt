// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import helium314.keyboard.secure.decrypt.DecryptedContactStatus
import helium314.keyboard.secure.decrypt.DecryptedMessage
import helium314.keyboard.secure.decrypt.SecureDisplayLease
import helium314.keyboard.secure.decrypt.SecureReplyToken
import helium314.keyboard.secure.decrypt.WipeablePlaintext
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeDecryptOperationTest {
    @Test
    fun callbackFailureClosesPlaintextAndCapabilities() {
        val bytes = "callback-failure-plaintext".encodeToByteArray()
        var replyClosed = false
        var leaseClosed = false
        val message = DecryptedMessage(
            WipeablePlaintext.takeOwnership(bytes),
            "local test label",
            DecryptedContactStatus.VERIFIED,
            object : SecureReplyToken {
                override fun close() {
                    replyClosed = true
                }
            },
            object : SecureDisplayLease {
                override fun markDisplayed() = Unit
                override fun close() {
                    leaseClosed = true
                }
            },
        )
        val operation = RuntimeDecryptOperation { throw IllegalStateException("test callback failure") }

        assertThrows(IllegalStateException::class.java) { operation.succeed(message) }

        assertTrue(bytes.all { it == 0.toByte() })
        assertTrue(replyClosed)
        assertTrue(leaseClosed)
    }
}
