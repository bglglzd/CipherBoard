// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class CiphertextSelectionTest {
    @Test
    fun acceptsAsciiBase64UrlPartsSeparatedByTransportWhitespace() {
        val result = CiphertextSelection.parse(" \nCB1:Abc_123-\r\n\tCB1:def ")

        val valid = assertIs<CiphertextSelection.Result.Valid>(result)
        assertEquals(listOf("CB1:Abc_123-", "CB1:def"), valid.parts)
    }

    @Test
    fun rejectsNonAsciiAndPaddingBeforeNativeParsing() {
        assertEquals(
            CiphertextSelection.Reason.INVALID_CHARACTERS,
            assertIs<CiphertextSelection.Result.Invalid>(
                CiphertextSelection.parse("CB1:кириллица"),
            ).reason,
        )
        assertEquals(
            CiphertextSelection.Reason.INVALID_CHARACTERS,
            assertIs<CiphertextSelection.Result.Invalid>(
                CiphertextSelection.parse("CB1:AA=="),
            ).reason,
        )
    }

    @Test
    fun rejectsMissingPrefixAndWhitespaceOnlyInput() {
        assertEquals(
            CiphertextSelection.Reason.INVALID_PREFIX,
            assertIs<CiphertextSelection.Result.Invalid>(
                CiphertextSelection.parse("not-a-cipherboard-message"),
            ).reason,
        )
        assertEquals(
            CiphertextSelection.Reason.EMPTY,
            assertIs<CiphertextSelection.Result.Invalid>(CiphertextSelection.parse(" \r\n\t")).reason,
        )
    }

    @Test
    fun enforcesPartCountAndPartSizeBeforeAllocatingMoreTokens() {
        val tooMany = List(CiphertextSelection.MAX_PARTS + 1) { "CB1:AA" }.joinToString(" ")
        assertEquals(
            CiphertextSelection.Reason.TOO_MANY_PARTS,
            assertIs<CiphertextSelection.Result.Invalid>(CiphertextSelection.parse(tooMany)).reason,
        )

        val oversized = "CB1:" + "A".repeat(CiphertextSelection.MAX_PART_CHARS)
        assertEquals(
            CiphertextSelection.Reason.PART_TOO_LARGE,
            assertIs<CiphertextSelection.Result.Invalid>(CiphertextSelection.parse(oversized)).reason,
        )

        val aggregateOversized = List(13) { "CB1:" + "A".repeat(31 * 1024) }.joinToString(" ")
        assertEquals(
            CiphertextSelection.Reason.TOO_LARGE,
            assertIs<CiphertextSelection.Result.Invalid>(
                CiphertextSelection.parse(aggregateOversized),
            ).reason,
        )
    }

    @Test
    fun copiesOnlyBoundedFrameworkTextWithoutCallingArbitraryToString() {
        assertEquals("CB1:abc", CiphertextSelection.copyBoundedUntrustedText("CB1:abc"))
        assertNull(
            CiphertextSelection.copyBoundedUntrustedText(
                object : CharSequence {
                    override val length: Int = 7
                    override fun get(index: Int): Char = "CB1:abc"[index]
                    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
                        throw AssertionError("must not inspect an arbitrary CharSequence")

                    override fun toString(): String =
                        throw AssertionError("must not stringify an arbitrary CharSequence")
                },
            ),
        )
        assertNull(
            CiphertextSelection.copyBoundedUntrustedText(
                "A".repeat(CiphertextSelection.MAX_SELECTION_CHARS + 1),
            ),
        )
    }
}
