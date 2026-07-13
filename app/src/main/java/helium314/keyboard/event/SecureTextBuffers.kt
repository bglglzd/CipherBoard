// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.event

import android.text.SpannableStringBuilder

internal fun StringBuilder.overwriteAndClear() {
    for (index in indices) setCharAt(index, '\u0000')
    setLength(0)
    trimToSize()
}

internal fun SpannableStringBuilder.overwriteAndClear() {
    if (isNotEmpty()) replace(0, length, String(CharArray(length)))
    clear()
    clearSpans()
}
