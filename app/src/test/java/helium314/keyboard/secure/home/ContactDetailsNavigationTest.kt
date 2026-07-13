// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ContactDetailsNavigationTest {
    @Test
    fun tokenResolvesToIndependentIdentifierCopy() {
        val source = ByteArray(32) { it.toByte() }
        val token = ContactDetailsNavigation.issue(source)
        source.fill(0)

        val first = requireNotNull(ContactDetailsNavigation.resolve(token))
        val expected = ByteArray(32) { it.toByte() }
        assertArrayEquals(expected, first)
        first.fill(0)

        val second = requireNotNull(ContactDetailsNavigation.resolve(token))
        assertArrayEquals(expected, second)
        second.fill(0)
        expected.fill(0)
        ContactDetailsNavigation.release(token)
    }

    @Test
    fun releaseMakesTokenUnresolvable() {
        val id = ByteArray(16) { 7 }
        val token = ContactDetailsNavigation.issue(id)
        id.fill(0)

        ContactDetailsNavigation.release(token)

        assertNull(ContactDetailsNavigation.resolve(token))
    }

    @Test
    fun tokensDoNotExposeIdentifierAndAreUnique() {
        val id = ByteArray(16) { 0x41 }
        val first = ContactDetailsNavigation.issue(id)
        val second = ContactDetailsNavigation.issue(id)
        id.fill(0)

        assertFalse(first.contains("AAAAAAAA"))
        assertFalse(first == second)
        ContactDetailsNavigation.release(first)
        ContactDetailsNavigation.release(second)
    }
}
