// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WipeableTextTest {
    @Test
    fun plaintextHolderWipesOwnedBytes() {
        val owned = "sensitive test value".encodeToByteArray()
        val holder = WipeablePlaintext.takeOwnership(owned)

        holder.close()

        assertTrue(owned.all { it == 0.toByte() })
        assertEquals(0, holder.size)
    }

    @Test
    fun utf8TextNeverRevealsContentThroughToStringAndCanBeClosed() {
        val bytes = "Русский, emoji 🔐, RTL العربية".encodeToByteArray()
        val holder = WipeablePlaintext.takeOwnership(bytes)
        val decoded = WipeableText.decodeUtf8(holder)!!

        assertEquals("[redacted]", decoded.toString())
        assertTrue(decoded.length > 0)
        decoded.close()
        holder.close()

        assertEquals(0, decoded.length)
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun malformedUtf8IsRejectedWithoutCreatingDisplayText() {
        val bytes = byteArrayOf(0xc3.toByte(), 0x28)
        val holder = WipeablePlaintext.takeOwnership(bytes)

        assertNull(WipeableText.decodeUtf8(holder))
        holder.close()
        assertTrue(bytes.all { it == 0.toByte() })
    }
}
