// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.text.Editable
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.view.MotionEvent
import android.view.ViewConfiguration
import android.widget.TextView
import kotlin.math.abs
import kotlin.math.max

/**
 * Non-focusable plaintext display with a local-only caret.
 *
 * It never exposes an Android editor connection, selection action mode, copy, or paste. Taps are
 * translated to offsets in [EmbeddedSecureInputConnection] by the controller.
 */
internal class SecureDraftView(context: Context) : TextView(context) {
    var onLocalCursorRequested: ((Int) -> Unit)? = null
    val displayBuffer: Editable = SpannableStringBuilder()

    private val cursorPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val touchSlop = ViewConfiguration.get(context).scaledTouchSlop
    private var localCursorOffset = -1
    private var downY = 0f
    private var lastY = 0f
    private var dragged = false

    init {
        setSpannableFactory(object : Spannable.Factory() {
            override fun newSpannable(source: CharSequence): Spannable =
                if (source === displayBuffer) displayBuffer as Spannable else SpannableStringBuilder(source)
        })
        setText(displayBuffer, BufferType.SPANNABLE)
    }

    fun setLocalCursor(offset: Int) {
        val bounded = offset.coerceIn(0, text?.length ?: 0)
        if (localCursorOffset == bounded) return
        localCursorOffset = bounded
        invalidate()
        post(::ensureLocalCursorVisible)
    }

    fun hideLocalCursor() {
        if (localCursorOffset < 0) return
        localCursorOffset = -1
        invalidate()
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                downY = event.y
                lastY = event.y
                dragged = false
                parent?.requestDisallowInterceptTouchEvent(true)
                return true
            }
            MotionEvent.ACTION_MOVE -> {
                val delta = lastY - event.y
                if (abs(event.y - downY) > touchSlop) dragged = true
                if (dragged) {
                    val layout = layout
                    if (layout != null) {
                        val viewport = height - compoundPaddingTop - compoundPaddingBottom
                        val maxScroll = max(0, layout.height - viewport)
                        scrollTo(scrollX, (scrollY + delta.toInt()).coerceIn(0, maxScroll))
                    }
                }
                lastY = event.y
                return true
            }
            MotionEvent.ACTION_UP -> {
                parent?.requestDisallowInterceptTouchEvent(false)
                if (!dragged) requestLocalCursor(event.x, event.y)
                performClick()
                return true
            }
            MotionEvent.ACTION_CANCEL -> {
                parent?.requestDisallowInterceptTouchEvent(false)
                return true
            }
        }
        return true
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val textLayout = layout ?: return
        if (localCursorOffset < 0) return
        val offset = localCursorOffset.coerceIn(0, text?.length ?: 0)
        val line = textLayout.getLineForOffset(offset)
        val x = totalPaddingLeft - scrollX + textLayout.getPrimaryHorizontal(offset)
        val top = totalPaddingTop - scrollY + textLayout.getLineTop(line)
        val bottom = totalPaddingTop - scrollY + textLayout.getLineBottom(line)
        cursorPaint.color = currentTextColor
        val cursorWidth = resources.displayMetrics.density.coerceAtLeast(1f) * 1.5f
        canvas.drawRect(x, top.toFloat(), x + cursorWidth, bottom.toFloat(), cursorPaint)
    }

    private fun requestLocalCursor(x: Float, y: Float) {
        val textLayout = layout ?: return
        if (textLayout.height <= 0) return
        val vertical = (y - totalPaddingTop + scrollY).toInt().coerceIn(0, textLayout.height - 1)
        val line = textLayout.getLineForVertical(vertical)
        val horizontal = x - totalPaddingLeft + scrollX
        onLocalCursorRequested?.invoke(textLayout.getOffsetForHorizontal(line, horizontal))
    }

    private fun ensureLocalCursorVisible() {
        val textLayout = layout ?: return
        if (localCursorOffset < 0) return
        val line = textLayout.getLineForOffset(localCursorOffset.coerceIn(0, text?.length ?: 0))
        val viewport = height - compoundPaddingTop - compoundPaddingBottom
        if (viewport <= 0) return
        val lineTop = textLayout.getLineTop(line)
        val lineBottom = textLayout.getLineBottom(line)
        val targetScroll = when {
            lineTop < scrollY -> lineTop
            lineBottom > scrollY + viewport -> lineBottom - viewport
            else -> scrollY
        }
        val maxScroll = max(0, textLayout.height - viewport)
        scrollTo(scrollX, targetScroll.coerceIn(0, maxScroll))
    }
}
