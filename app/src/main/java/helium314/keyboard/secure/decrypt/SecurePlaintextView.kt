// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.decrypt

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.os.Build
import android.text.Layout
import android.text.StaticLayout
import android.text.TextDirectionHeuristics
import android.text.TextPaint
import android.util.TypedValue
import android.view.View
import kotlin.math.max

/** Drawing-only plaintext surface: no selection, clipboard action mode, autofill or accessibility text. */
internal class SecurePlaintextView(context: Context) : View(context) {
    private val paint = TextPaint(TextPaint.ANTI_ALIAS_FLAG).apply {
        textSize = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_SP,
            18f,
            resources.displayMetrics,
        )
        color = resolveTextColor(context)
    }
    private var secureText: WipeableText? = null
    private var textLayout: StaticLayout? = null
    private var layoutWidth = 0
    private var firstDrawPending = false

    internal var beforeSecureTextDraw: (() -> Boolean)? = null
    internal var onSecureTextDrawn: (() -> Unit)? = null

    init {
        minimumHeight = dp(context, 160)
        setPadding(0, dp(context, 12), 0, dp(context, 12))
        isSaveEnabled = false
        isFocusable = false
        isFocusableInTouchMode = false
        isLongClickable = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= 26) {
            importantForAutofill = IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        if (Build.VERSION.SDK_INT >= 30) {
            importantForContentCapture = IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        }
        contentDescription = null
    }

    fun setSecureText(text: WipeableText) {
        clearSecureText()
        secureText = text
        firstDrawPending = true
        requestLayout()
        invalidate()
    }

    fun clearSecureText() {
        secureText?.close()
        secureText = null
        textLayout = null
        layoutWidth = 0
        firstDrawPending = false
        invalidate()
    }

    fun setSecureTextColor(color: Int) {
        paint.color = color
        textLayout = null
        layoutWidth = 0
        invalidate()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val measuredWidth = resolveSize(suggestedMinimumWidth, widthMeasureSpec)
        val contentWidth = max(1, measuredWidth - paddingLeft - paddingRight)
        rebuildLayout(contentWidth)
        val desiredHeight = max(
            minimumHeight,
            (textLayout?.height ?: 0) + paddingTop + paddingBottom,
        )
        setMeasuredDimension(measuredWidth, resolveSize(desiredHeight, heightMeasureSpec))
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val layout = textLayout ?: return
        if (firstDrawPending && beforeSecureTextDraw?.invoke() == false) return
        canvas.save()
        canvas.translate(paddingLeft.toFloat(), paddingTop.toFloat())
        layout.draw(canvas)
        canvas.restore()
        if (firstDrawPending) {
            firstDrawPending = false
            onSecureTextDrawn?.invoke()
        }
    }

    @SuppressLint("WrongConstant")
    private fun rebuildLayout(width: Int) {
        val text = secureText ?: run {
            textLayout = null
            return
        }
        if (textLayout != null && layoutWidth == width) return
        layoutWidth = width
        textLayout = StaticLayout.Builder.obtain(text, 0, text.length, paint, width)
            .setAlignment(Layout.Alignment.ALIGN_NORMAL)
            .setIncludePad(true)
            .setTextDirection(TextDirectionHeuristics.FIRSTSTRONG_LTR)
            .setBreakStrategy(Layout.BREAK_STRATEGY_HIGH_QUALITY)
            .build()
    }

    companion object {
        private fun resolveTextColor(context: Context): Int {
            val attributes = context.obtainStyledAttributes(intArrayOf(android.R.attr.textColorPrimary))
            return try {
                attributes.getColor(0, 0xff202124.toInt())
            } finally {
                attributes.recycle()
            }
        }

        private fun dp(context: Context, value: Int): Int = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat(),
            context.resources.displayMetrics,
        ).toInt()
    }
}
