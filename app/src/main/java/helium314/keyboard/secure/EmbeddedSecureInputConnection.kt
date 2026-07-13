// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.text.Editable
import android.text.Selection
import android.text.SpannableStringBuilder
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.BaseInputConnection
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Process-local editor used by HeliBoard while Private mode is active.
 *
 * This connection is never returned to the host application. RichInputConnection resolves to it
 * instead of the remote host connection, so composing text, cursor operations, hardware keys and
 * gesture results remain in this bounded in-memory editor.
 */
internal class EmbeddedSecureInputConnection(
    targetView: View,
    private val acceptsInput: () -> Boolean,
    private val onChanged: (EmbeddedSecureInputConnection) -> Unit,
) : BaseInputConnection(targetView, true) {
    private val content = SpannableStringBuilder()
    private var batchDepth = 0
    private var changedInBatch = false

    var revision: Long = 0
        private set

    init {
        Selection.setSelection(content, 0)
    }

    override fun getEditable(): Editable = content

    override fun beginBatchEdit(): Boolean {
        batchDepth++
        return true
    }

    override fun endBatchEdit(): Boolean {
        if (batchDepth > 0) batchDepth--
        if (batchDepth == 0 && changedInBatch) {
            changedInBatch = false
            notifyChanged()
        }
        return true
    }

    override fun commitText(text: CharSequence?, newCursorPosition: Int): Boolean =
        mutate(text) { super.commitText(it, newCursorPosition) }

    override fun setComposingText(text: CharSequence?, newCursorPosition: Int): Boolean =
        mutate(text) { super.setComposingText(it, newCursorPosition) }

    override fun setComposingRegion(start: Int, end: Int): Boolean =
        mutateWithoutGrowth { super.setComposingRegion(start, end) }

    override fun finishComposingText(): Boolean =
        mutateWithoutGrowth { super.finishComposingText() }

    override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean =
        mutateWithoutGrowth { super.deleteSurroundingText(beforeLength, afterLength) }

    override fun deleteSurroundingTextInCodePoints(beforeLength: Int, afterLength: Int): Boolean =
        mutateWithoutGrowth { super.deleteSurroundingTextInCodePoints(beforeLength, afterLength) }

    override fun setSelection(start: Int, end: Int): Boolean =
        mutateWithoutGrowth { super.setSelection(start, end) }

    override fun sendKeyEvent(event: KeyEvent): Boolean {
        if (event.action != KeyEvent.ACTION_DOWN) return true
        return when (event.keyCode) {
            KeyEvent.KEYCODE_DEL -> deleteSurroundingTextInCodePoints(1, 0)
            KeyEvent.KEYCODE_ENTER -> commitText("\n", 1)
            KeyEvent.KEYCODE_DPAD_LEFT -> moveSelectionByCodePoint(-1)
            KeyEvent.KEYCODE_DPAD_RIGHT -> moveSelectionByCodePoint(1)
            else -> {
                val codePoint = event.unicodeChar
                if (codePoint == 0) false else commitText(String(Character.toChars(codePoint)), 1)
            }
        }
    }

    override fun performEditorAction(actionCode: Int): Boolean = commitText("\n", 1)

    override fun performContextMenuAction(id: Int): Boolean = false

    override fun performPrivateCommand(action: String?, data: android.os.Bundle?): Boolean = false

    fun isEmpty(): Boolean = content.isEmpty()

    fun codePointCount(): Int = Character.codePointCount(content, 0, content.length)

    fun selectionStart(): Int = Selection.getSelectionStart(content).coerceAtLeast(0)

    fun selectionEnd(): Int = Selection.getSelectionEnd(content).coerceAtLeast(0)

    fun utf8Length(): Int? = strictUtf8Length(content)

    /** Returns a fresh owned byte array. SecureKeyboardRuntime consumes and wipes it. */
    fun copyUtf8(): ByteArray {
        val byteCount = strictUtf8Length(content)
            ?: throw IllegalArgumentException("Private draft contains invalid Unicode")
        val result = ByteArray(byteCount)
        if (byteCount == 0) return result
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val output = ByteBuffer.wrap(result)
        val input = CharBuffer.wrap(content)
        val encodeResult = encoder.encode(input, output, true)
        if (encodeResult.isError) encodeResult.throwException()
        check(encodeResult.isUnderflow) { "Unexpected UTF-8 encoder overflow" }
        val flushResult = encoder.flush(output)
        if (flushResult.isError) flushResult.throwException()
        check(flushResult.isUnderflow) { "Unexpected UTF-8 encoder overflow" }
        return result
    }

    fun copyInto(target: Editable) {
        var prefix = 0
        val sharedLength = minOf(target.length, content.length)
        while (prefix < sharedLength && target[prefix] == content[prefix]) prefix++

        var suffix = 0
        while (
            suffix < sharedLength - prefix &&
            target[target.length - suffix - 1] == content[content.length - suffix - 1]
        ) {
            suffix++
        }

        val targetEnd = target.length - suffix
        val contentEnd = content.length - suffix
        wipeRange(target, prefix, targetEnd)
        target.replace(prefix, targetEnd, content, prefix, contentEnd)
    }

    fun wipe() {
        wipeEditable(content)
        Selection.setSelection(content, 0)
        batchDepth = 0
        changedInBatch = false
        revision++
        onChanged(this)
    }

    override fun closeConnection() {
        wipe()
        super.closeConnection()
    }

    private fun mutate(candidate: CharSequence?, operation: (CharSequence) -> Boolean): Boolean {
        if (!acceptsInput()) return false
        val value = candidate ?: ""
        if (value.length > MAX_DRAFT_UTF16_CHARS || content.length > MAX_DRAFT_UTF16_CHARS - value.length) {
            return false
        }
        val accepted = operation(value)
        if (accepted) markChanged()
        return accepted
    }

    private inline fun mutateWithoutGrowth(operation: () -> Boolean): Boolean {
        if (!acceptsInput()) return false
        val accepted = operation()
        if (accepted) markChanged()
        return accepted
    }

    private fun moveSelectionByCodePoint(direction: Int): Boolean {
        val current = Selection.getSelectionEnd(content).coerceIn(0, content.length)
        val next = when {
            direction < 0 && current > 0 -> Character.offsetByCodePoints(content, current, -1)
            direction > 0 && current < content.length -> Character.offsetByCodePoints(content, current, 1)
            else -> current
        }
        return setSelection(next, next)
    }

    private fun markChanged() {
        if (batchDepth > 0) {
            changedInBatch = true
        } else {
            notifyChanged()
        }
    }

    private fun notifyChanged() {
        revision++
        onChanged(this)
    }

    companion object {
        // The embedded editor redraws inside the latency-sensitive IME process. Keep its volatile
        // draft well below the protocol limit so typing and screen-off cleanup stay bounded.
        const val MAX_DRAFT_UTF16_CHARS = 32 * 1024
        private const val WIPE_BLOCK_CHARS = 4 * 1024
        private val WIPE_BLOCK = CharArray(WIPE_BLOCK_CHARS) { '\u0000' }.concatToString()

        internal fun strictUtf8Length(value: CharSequence): Int? {
            var bytes = 0L
            var index = 0
            while (index < value.length) {
                val char = value[index]
                when {
                    Character.isHighSurrogate(char) -> {
                        if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) return null
                        bytes += 4
                        index += 2
                    }
                    Character.isLowSurrogate(char) -> return null
                    char.code <= 0x7f -> {
                        bytes += 1
                        index++
                    }
                    char.code <= 0x7ff -> {
                        bytes += 2
                        index++
                    }
                    else -> {
                        bytes += 3
                        index++
                    }
                }
                if (bytes > Int.MAX_VALUE) return null
            }
            return bytes.toInt()
        }

        internal fun wipeEditable(value: Editable, clearSpans: Boolean = true) {
            wipeRange(value, 0, value.length)
            if (clearSpans) value.clearSpans()
            value.clear()
        }

        private fun wipeRange(value: Editable, start: Int, end: Int) {
            var offset = 0
            while (start + offset < end) {
                val blockLength = minOf(WIPE_BLOCK_CHARS, end - start - offset)
                value.replace(start + offset, start + offset + blockLength, WIPE_BLOCK, 0, blockLength)
                offset += blockLength
            }
        }
    }
}
