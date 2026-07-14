// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.TransportPresentation
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PendingCiphertextCodecTest {
    @Test
    fun legacyV1MigratesAsCompactPresentation() {
        val parts = listOf("CB1:Abc_123-", "CB1:def")
        val decoded = PendingCiphertextCodec.decode(encodeLegacyV1(parts))

        assertEquals(TransportPresentation.COMPACT, decoded.presentation)
        assertEquals(parts, decoded.parts)
    }

    @Test
    fun v2RoundTripsCanonicalPartsAndEveryPresentation() {
        val parts = listOf("CB1:Abc_123-", "CB1:def")

        TransportPresentation.entries.forEach { presentation ->
            val encoded = PendingCiphertextCodec.encode(parts, presentation)
            val decoded = PendingCiphertextCodec.decode(encoded)
            assertEquals(presentation, decoded.presentation)
            assertEquals(parts, decoded.parts)
        }
    }

    @Test
    fun rejectsTamperedOrNonCanonicalRecords() {
        val encoded = PendingCiphertextCodec.encode(
            listOf("CB1:Abc_123-"),
            TransportPresentation.ENGLISH_WORDS,
        )
        val changedMagic = encoded.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertFailsWith<IllegalArgumentException> { PendingCiphertextCodec.decode(changedMagic) }
        assertFailsWith<IllegalArgumentException> {
            PendingCiphertextCodec.decode(encoded + byteArrayOf(0))
        }
        assertFailsWith<IllegalArgumentException> {
            PendingCiphertextCodec.decode(encoded.copyOf(7))
        }
        assertFailsWith<IllegalArgumentException> {
            PendingCiphertextCodec.decode(encoded.copyOf(encoded.size - 1))
        }
        assertFailsWith<IllegalArgumentException> {
            PendingCiphertextCodec.encode(listOf("not-canonical"), TransportPresentation.COMPACT)
        }
    }

    @Test
    fun rejectsUnknownV2Presentation() {
        val encoded = PendingCiphertextCodec.encode(
            listOf("CB1:Abc_123-"),
            TransportPresentation.COMPACT,
        )
        encoded[PRESENTATION_OFFSET] = 0x7f

        assertFailsWith<IllegalArgumentException> { PendingCiphertextCodec.decode(encoded) }
    }

    private fun encodeLegacyV1(parts: List<String>): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { writer ->
            writer.writeInt(MAGIC)
            writer.writeByte(PendingCiphertextCodec.LEGACY_VERSION)
            writer.writeShort(parts.size)
            parts.forEach { part ->
                val bytes = part.toByteArray(StandardCharsets.US_ASCII)
                writer.writeInt(bytes.size)
                writer.write(bytes)
                bytes.fill(0)
            }
        }
        return output.toByteArray()
    }

    private companion object {
        const val MAGIC = 0x4342504f
        const val PRESENTATION_OFFSET = 5
    }
}
