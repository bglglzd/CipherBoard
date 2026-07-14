// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import kotlin.test.Test
import kotlin.test.assertEquals

class SecureReplyTransitionTest {
    @Test
    fun `reply wipes previous recipient draft before switching contact`() {
        val operations = mutableListOf<String>()

        performSecureReplyTransition(
            clearPrivateDraft = { operations += "wipe" },
            enterEncryptMode = { operations += "encrypt-mode" },
            selectReplyContact = { operations += "reply-contact" },
        )

        assertEquals(listOf("wipe", "encrypt-mode", "reply-contact"), operations)
    }
}
