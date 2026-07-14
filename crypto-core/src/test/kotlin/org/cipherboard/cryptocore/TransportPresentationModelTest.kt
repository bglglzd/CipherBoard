package org.cipherboard.cryptocore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TransportPresentationModelTest {
    @Test
    fun presentationWireValuesAreStable() {
        assertEquals(TransportPresentation.COMPACT, TransportPresentation.fromWire(0))
        assertEquals(TransportPresentation.RUSSIAN_WORDS, TransportPresentation.fromWire(1))
        assertEquals(TransportPresentation.ENGLISH_WORDS, TransportPresentation.fromWire(2))
        assertFailsWith<IllegalArgumentException> { TransportPresentation.fromWire(3) }
    }

    @Test
    fun decodedPresentationDoesNotPrintCiphertext() {
        val decoded = PresentationDecoded(
            TransportPresentation.RUSSIAN_WORDS,
            listOf("CB1:must-not-appear"),
        )
        assertEquals(
            "PresentationDecoded(presentation=RUSSIAN_WORDS,parts=1)",
            decoded.toString(),
        )
    }
}
