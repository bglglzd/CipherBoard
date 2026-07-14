// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.cryptocore.TransportPresentation
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

/** Strict length-prefixed encoding used only inside an encrypted pending-outbound record. */
internal object PendingCiphertextCodec {
    internal const val LEGACY_VERSION = 1
    internal const val CURRENT_VERSION = 2
    private const val MAX_PARTS = 128
    private const val MAX_PART_BYTES = 32 * 1024
    private const val MAX_ENCODED_BYTES = 5 * 1024 * 1024

    class Decoded(
        val presentation: TransportPresentation,
        parts: List<String>,
    ) {
        val parts = parts.toList()

        override fun toString(): String =
            "PendingCiphertextCodec.Decoded(presentation=$presentation,parts=${parts.size})"
    }

    fun encode(parts: List<String>, presentation: TransportPresentation): ByteArray {
        require(parts.size in 1..MAX_PARTS)
        val encodedParts = ArrayList<ByteArray>(parts.size)
        try {
            parts.forEach { part ->
                require(part.isCanonicalEnvelopeCandidate())
                require(part.all { it.code in 0..0x7f })
                val encoded = part.toByteArray(StandardCharsets.US_ASCII)
                require(encoded.size in 1..MAX_PART_BYTES)
                encodedParts += encoded
            }
            val output = ByteArrayOutputStream()
            DataOutputStream(output).use { writer ->
                writer.writeInt(MAGIC)
                writer.writeByte(CURRENT_VERSION)
                writer.writeByte(presentation.toWireValue())
                writer.writeShort(encodedParts.size)
                encodedParts.forEach { encoded ->
                    writer.writeInt(encoded.size)
                    writer.write(encoded)
                }
            }
            return output.toByteArray().also { require(it.size <= MAX_ENCODED_BYTES) }
        } finally {
            encodedParts.forEach { it.fill(0) }
        }
    }

    fun decode(encoded: ByteArray): Decoded {
        require(encoded.size in LEGACY_HEADER_BYTES..MAX_ENCODED_BYTES)
        return DataInputStream(ByteArrayInputStream(encoded)).use { reader ->
            require(reader.readInt() == MAGIC)
            val presentation = when (reader.readUnsignedByte()) {
                LEGACY_VERSION -> TransportPresentation.COMPACT
                CURRENT_VERSION -> {
                    require(reader.available() >= V2_HEADER_REMAINDER_BYTES)
                    presentationFromWire(reader.readUnsignedByte())
                }
                else -> throw IllegalArgumentException("Unsupported pending ciphertext version")
            }
            val count = reader.readUnsignedShort()
            require(count in 1..MAX_PARTS)
            val parts = ArrayList<String>(count)
            repeat(count) {
                require(reader.available() >= Int.SIZE_BYTES)
                val length = reader.readInt()
                require(length in 1..MAX_PART_BYTES && length <= reader.available())
                val bytes = ByteArray(length)
                try {
                    reader.readFully(bytes)
                    require(bytes.all { it.toInt() in 0..0x7f })
                    val part = String(bytes, StandardCharsets.US_ASCII)
                    require(part.isCanonicalEnvelopeCandidate())
                    parts += part
                } finally {
                    bytes.fill(0)
                }
            }
            require(reader.available() == 0)
            Decoded(presentation, parts)
        }
    }

    private fun TransportPresentation.toWireValue(): Int = when (this) {
        TransportPresentation.COMPACT -> 0
        TransportPresentation.RUSSIAN_WORDS -> 1
        TransportPresentation.ENGLISH_WORDS -> 2
    }

    private fun presentationFromWire(value: Int): TransportPresentation = when (value) {
        0 -> TransportPresentation.COMPACT
        1 -> TransportPresentation.RUSSIAN_WORDS
        2 -> TransportPresentation.ENGLISH_WORDS
        else -> throw IllegalArgumentException("Unknown pending ciphertext presentation")
    }

    private fun String.isCanonicalEnvelopeCandidate(): Boolean =
        length > ENVELOPE_PREFIX.length && startsWith(ENVELOPE_PREFIX) &&
            drop(ENVELOPE_PREFIX.length).all { character ->
                character in 'A'..'Z' || character in 'a'..'z' || character in '0'..'9' ||
                    character == '-' || character == '_'
            }

    private const val MAGIC = 0x4342504f // CBPO
    private const val LEGACY_HEADER_BYTES = 7
    private const val V2_HEADER_REMAINDER_BYTES = 3
    private const val ENVELOPE_PREFIX = "CB1:"
}
