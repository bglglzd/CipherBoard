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
    const val MAX_WORD_TOKENS = 32 * 1024
    const val MAX_WORD_CHARS = 10
    // Covers the 256 KiB decoded aggregate while keeping UTF-16 Intent data below Binder limits.
    const val MAX_SELECTION_CHARS = 384 * 1024

    sealed interface Result {
        class Valid(parts: List<String>) : Result {
            val parts: List<String> = parts.toList()

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
        MIXED_PRESENTATION,
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
        val length = try {
            source.length
        } catch (_: RuntimeException) {
            return Result.Invalid(Reason.INVALID_CHARACTERS)
        }
        if (length == 0) return Result.Invalid(Reason.EMPTY)
        if (length > MAX_SELECTION_CHARS) return Result.Invalid(Reason.TOO_LARGE)
        val stableSource = source.stableCopy(length)
            ?: return Result.Invalid(Reason.INVALID_CHARACTERS)
        return when (val scan = scan(stableSource)) {
            is Scan.Invalid -> Result.Invalid(scan.reason)
            is Scan.Valid -> when (scan.presentation) {
                CandidatePresentation.COMPACT -> Result.Valid(stableSource.compactParts())
                CandidatePresentation.ENGLISH_WORDS,
                CandidatePresentation.RUSSIAN_WORDS,
                -> Result.Valid(listOf(stableSource))
            }
        }
    }

    @JvmStatic
    fun isCandidate(source: CharSequence?): Boolean = try {
        source != null && scan(source) is Scan.Valid
    } catch (_: RuntimeException) {
        false
    }

    private fun scan(source: CharSequence): Scan {
        if (source.isEmpty()) return Scan.Invalid(Reason.EMPTY)
        if (source.length > MAX_SELECTION_CHARS) return Scan.Invalid(Reason.TOO_LARGE)

        var presentation: CandidatePresentation? = null
        var tokenCount = 0
        var index = 0
        while (index < source.length) {
            while (index < source.length && source[index].isTransportWhitespace()) index++
            if (index == source.length) break

            val start = index
            val tokenPresentation = presentation ?: source.detectPresentation(index)
                ?: return Scan.Invalid(Reason.INVALID_CHARACTERS)
            while (index < source.length && !source[index].isTransportWhitespace()) {
                val character = source[index]
                val valid = when (tokenPresentation) {
                    CandidatePresentation.COMPACT -> character.isEnvelopeCharacter()
                    CandidatePresentation.ENGLISH_WORDS -> character in 'a'..'z'
                    CandidatePresentation.RUSSIAN_WORDS -> character in '\u0430'..'\u044f'
                }
                if (!valid) {
                    val mixed = tokenPresentation.isWordPresentation() &&
                        (character in 'a'..'z' || character in '\u0430'..'\u044f')
                    return Scan.Invalid(
                        if (mixed) Reason.MIXED_PRESENTATION else Reason.INVALID_CHARACTERS,
                    )
                }
                val maximum = if (tokenPresentation == CandidatePresentation.COMPACT) {
                    MAX_PART_CHARS
                } else {
                    MAX_WORD_CHARS
                }
                if (index - start >= maximum) return Scan.Invalid(Reason.PART_TOO_LARGE)
                index++
            }
            if (tokenPresentation == CandidatePresentation.COMPACT &&
                (index - start == PREFIX.length || !source.startsWithPrefixAt(start))
            ) {
                return Scan.Invalid(Reason.INVALID_PREFIX)
            }
            val maximumTokens = if (tokenPresentation == CandidatePresentation.COMPACT) {
                MAX_PARTS
            } else {
                MAX_WORD_TOKENS
            }
            if (tokenCount == maximumTokens) return Scan.Invalid(Reason.TOO_MANY_PARTS)
            tokenCount++
            presentation = tokenPresentation
        }
        return presentation?.let(Scan::Valid) ?: Scan.Invalid(Reason.EMPTY)
    }

    private fun CharSequence.stableCopy(length: Int): String? {
        if (this is String) return this
        val copy = CharArray(length)
        return try {
            for (index in 0 until length) copy[index] = this[index]
            copy.concatToString()
        } catch (_: RuntimeException) {
            null
        } finally {
            copy.fill('\u0000')
        }
    }

    private fun String.compactParts(): List<String> {
        val parts = ArrayList<String>(minOf(4, MAX_PARTS))
        var index = 0
        while (index < length) {
            while (index < length && this[index].isTransportWhitespace()) index++
            if (index == length) break
            val start = index
            while (index < length && !this[index].isTransportWhitespace()) index++
            parts += substring(start, index)
        }
        return parts
    }

    private fun CharSequence.detectPresentation(index: Int): CandidatePresentation? = when {
        startsWithPrefixAt(index) -> CandidatePresentation.COMPACT
        this[index] in 'a'..'z' -> CandidatePresentation.ENGLISH_WORDS
        this[index] in '\u0430'..'\u044f' -> CandidatePresentation.RUSSIAN_WORDS
        else -> null
    }

    private fun CharSequence.startsWithPrefixAt(index: Int): Boolean =
        index + PREFIX.length <= length && PREFIX.indices.all { offset ->
            this[index + offset] == PREFIX[offset]
        }

    private fun Char.isTransportWhitespace(): Boolean =
        this == ' ' || this == '\n' || this == '\r' || this == '\t' || this == '\u000c'

    private fun Char.isEnvelopeCharacter(): Boolean =
        this in 'A'..'Z' || this in 'a'..'z' || this in '0'..'9' ||
            this == '-' || this == '_' || this == ':'

    private fun CandidatePresentation.isWordPresentation(): Boolean =
        this != CandidatePresentation.COMPACT

    private sealed interface Scan {
        data class Valid(val presentation: CandidatePresentation) : Scan

        data class Invalid(val reason: Reason) : Scan
    }

    private enum class CandidatePresentation {
        COMPACT,
        ENGLISH_WORDS,
        RUSSIAN_WORDS,
    }

    private const val PREFIX = "CB1:"
}
