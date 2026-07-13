// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.text.GetChars
import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** CharSequence backed by an explicitly wipeable array; toString deliberately never reveals text. */
internal class WipeableText private constructor(
    private var chars: CharArray?,
) : CharSequence, GetChars, Closeable {
    override val length: Int
        get() = chars?.size ?: 0

    override fun get(index: Int): Char = chars?.get(index)
        ?: throw IndexOutOfBoundsException("Text is closed")

    override fun getChars(start: Int, end: Int, dest: CharArray, destoff: Int) {
        val current = chars ?: throw IndexOutOfBoundsException("Text is closed")
        current.copyInto(dest, destoff, start, end)
    }

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence {
        require(startIndex in 0..endIndex && endIndex <= length)
        return Slice(this, startIndex, endIndex)
    }

    override fun toString(): String = "[redacted]"

    override fun close() {
        chars?.fill('\u0000')
        chars = null
    }

    private class Slice(
        private val owner: WipeableText,
        private val start: Int,
        private val end: Int,
    ) : CharSequence, GetChars {
        override val length: Int get() = end - start
        override fun get(index: Int): Char {
            require(index in 0 until length)
            return owner[start + index]
        }

        override fun getChars(start: Int, end: Int, dest: CharArray, destoff: Int) {
            require(start in 0..end && end <= length)
            owner.getChars(this.start + start, this.start + end, dest, destoff)
        }

        override fun subSequence(startIndex: Int, endIndex: Int): CharSequence {
            require(startIndex in 0..endIndex && endIndex <= length)
            return Slice(owner, start + startIndex, start + endIndex)
        }

        override fun toString(): String = "[redacted]"
    }

    companion object {
        fun decodeUtf8(source: WipeablePlaintext): WipeableText? = source.withBytes { bytes ->
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val decoded = try {
                decoder.decode(ByteBuffer.wrap(bytes))
            } catch (_: Exception) {
                return@withBytes null
            }
            try {
                val owned = CharArray(decoded.remaining())
                decoded.get(owned)
                WipeableText(owned)
            } finally {
                if (decoded.hasArray()) decoded.array().fill('\u0000')
            }
        }
    }
}
