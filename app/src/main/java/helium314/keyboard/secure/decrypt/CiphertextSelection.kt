// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.content.Intent
import android.text.SpannableString
import android.text.SpannableStringBuilder
import android.text.SpannedString

/** Allocation-bounded first-pass validation before data reaches the native envelope parser. */
object CiphertextSelection {
    const val MAX_PARTS = 128
    const val MAX_PART_CHARS = 32 * 1024
    // Covers the 256 KiB decoded aggregate while keeping UTF-16 Intent data below Binder limits.
    const val MAX_SELECTION_CHARS = 384 * 1024

    sealed interface Result {
        class Valid(val parts: List<String>) : Result {
            override fun toString(): String = "CiphertextSelection.Valid(parts=${parts.size})"
        }

        data class Invalid(val reason: Reason) : Result
    }

    enum class Reason {
        EMPTY,
        TOO_LARGE,
        TOO_MANY_PARTS,
        PART_TOO_LARGE,
        INVALID_CHARACTERS,
        INVALID_PREFIX,
    }

    fun readBoundedTextExtra(sourceIntent: Intent, key: String): String? = try {
        copyBoundedUntrustedText(sourceIntent.getCharSequenceExtra(key))
    } catch (_: RuntimeException) {
        null
    }

    fun copyBoundedUntrustedText(source: CharSequence?): String? {
        source ?: return null
        if (source !is String && source !is SpannedString && source !is SpannableString &&
            source !is SpannableStringBuilder
        ) {
            return null
        }
        val length = try {
            source.length
        } catch (_: RuntimeException) {
            return null
        }
        if (length !in 1..MAX_SELECTION_CHARS) return null
        if (source is String) return source

        val copy = CharArray(length)
        return try {
            for (index in 0 until length) copy[index] = source[index]
            copy.concatToString()
        } catch (_: RuntimeException) {
            null
        } finally {
            copy.fill('\u0000')
        }
    }

    fun parse(source: CharSequence): Result {
        if (source.isEmpty()) return Result.Invalid(Reason.EMPTY)
        if (source.length > MAX_SELECTION_CHARS) return Result.Invalid(Reason.TOO_LARGE)

        val parts = ArrayList<String>(minOf(4, MAX_PARTS))
        var index = 0
        while (index < source.length) {
            while (index < source.length && source[index].isTransportWhitespace()) index++
            if (index == source.length) break

            val start = index
            while (index < source.length && !source[index].isTransportWhitespace()) {
                val character = source[index]
                if (!character.isEnvelopeCharacter()) return Result.Invalid(Reason.INVALID_CHARACTERS)
                if (index - start >= MAX_PART_CHARS) return Result.Invalid(Reason.PART_TOO_LARGE)
                index++
            }
            if (index - start > MAX_PART_CHARS) return Result.Invalid(Reason.PART_TOO_LARGE)
            if (parts.size == MAX_PARTS) return Result.Invalid(Reason.TOO_MANY_PARTS)

            val part = source.subSequence(start, index).toString()
            if (!part.startsWith(PREFIX) || part.length == PREFIX.length) {
                return Result.Invalid(Reason.INVALID_PREFIX)
            }
            parts += part
        }
        return if (parts.isEmpty()) Result.Invalid(Reason.EMPTY) else Result.Valid(parts)
    }

    private fun Char.isTransportWhitespace(): Boolean =
        this == ' ' || this == '\n' || this == '\r' || this == '\t' || this == '\u000c'

    private fun Char.isEnvelopeCharacter(): Boolean =
        this in 'A'..'Z' || this in 'a'..'z' || this in '0'..'9' ||
            this == '-' || this == '_' || this == ':'

    private const val PREFIX = "CB1:"
}
