// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.Context
import helium314.keyboard.latin.R
import org.cipherboard.cryptocore.CipherBoardCrypto
import org.cipherboard.cryptocore.TransportPresentation

internal data class MessagePresentationEstimate(
    val value: Int,
    val unit: MessagePresentationEstimateUnit,
)

internal enum class MessagePresentationEstimateUnit {
    ENCRYPTED_CHARACTERS,
    ENCODED_WORDS,
}

internal fun estimateMessagePresentation(
    plaintextBytes: Int,
    presentation: TransportPresentation,
): MessagePresentationEstimate {
    require(plaintextBytes >= 0)
    if (plaintextBytes == 0) {
        return MessagePresentationEstimate(
            0,
            if (presentation == TransportPresentation.COMPACT) {
                MessagePresentationEstimateUnit.ENCRYPTED_CHARACTERS
            } else {
                MessagePresentationEstimateUnit.ENCODED_WORDS
            },
        )
    }

    val encryptedPayloadBytes =
        (plaintextBytes.toLong() + OLM_INPUT_OVERHEAD_ESTIMATE_BYTES).base64UrlCharacters()
    val partCount = encryptedPayloadBytes.ceilDivide(UNIVERSAL_CHUNK_BYTES).coerceAtLeast(1)
    val envelopeBytes = encryptedPayloadBytes + partCount * ENVELOPE_BINARY_OVERHEAD_ESTIMATE_BYTES
    return if (presentation == TransportPresentation.COMPACT) {
        val characters = partCount * COMPACT_PREFIX_CHARACTERS +
            envelopeBytes.base64UrlCharacters() + (partCount - 1)
        MessagePresentationEstimate(
            characters.toBoundedInt(),
            MessagePresentationEstimateUnit.ENCRYPTED_CHARACTERS,
        )
    } else {
        val wrapperBytes = WORD_WRAPPER_HEADER_BYTES + partCount * WORD_PART_LENGTH_BYTES + envelopeBytes
        val words = (wrapperBytes * BITS_PER_BYTE).ceilDivide(WORD_BITS)
        MessagePresentationEstimate(words.toBoundedInt(), MessagePresentationEstimateUnit.ENCODED_WORDS)
    }
}

internal fun maximumPlaintextBytes(presentation: TransportPresentation): Int =
    if (presentation == TransportPresentation.COMPACT) {
        CipherBoardCrypto.MAX_PLAINTEXT_BYTES
    } else {
        WORD_PRESENTATION_PLAINTEXT_LIMIT_BYTES
    }

internal fun Context.messagePresentationEstimateText(
    characters: Int,
    plaintextBytes: Int,
    presentation: TransportPresentation,
): String {
    val estimate = estimateMessagePresentation(plaintextBytes, presentation)
    val detail = when (estimate.unit) {
        MessagePresentationEstimateUnit.ENCRYPTED_CHARACTERS -> resources.getQuantityString(
            R.plurals.secure_estimated_encrypted_characters,
            estimate.value,
            estimate.value,
        )
        MessagePresentationEstimateUnit.ENCODED_WORDS -> resources.getQuantityString(
            R.plurals.secure_estimated_encoded_words,
            estimate.value,
            estimate.value,
        )
    }
    val characterCount = resources.getQuantityString(
        R.plurals.secure_character_count,
        characters,
        characters,
    )
    return getString(R.string.secure_size_estimate, characterCount, detail)
}

private fun Long.ceilDivide(divisor: Long): Long = (this + divisor - 1) / divisor

private fun Long.base64UrlCharacters(): Long = (this * 4 + 2) / 3

private fun Long.toBoundedInt(): Int = coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

private const val OLM_INPUT_OVERHEAD_ESTIMATE_BYTES = 512L
private const val ENVELOPE_BINARY_OVERHEAD_ESTIMATE_BYTES = 96L
private const val UNIVERSAL_CHUNK_BYTES = 16L * 1024L
private const val COMPACT_PREFIX_CHARACTERS = 4L
private const val WORD_WRAPPER_HEADER_BYTES = 20L
private const val WORD_PART_LENGTH_BYTES = 4L
private const val BITS_PER_BYTE = 8L
private const val WORD_BITS = 12L

// Leaves headroom inside the native 48 KiB word wrapper for Olm and envelope metadata.
private const val WORD_PRESENTATION_PLAINTEXT_LIMIT_BYTES = 32 * 1024
