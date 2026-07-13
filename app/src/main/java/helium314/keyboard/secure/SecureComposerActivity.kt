// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.Space
import android.widget.TextView
import android.view.WindowManager
import androidx.activity.ComponentActivity
import android.util.TypedValue
import helium314.keyboard.latin.R

class SecureComposerActivity : ComponentActivity() {
    private fun dpToPx(dp: Int) = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP,
        dp.toFloat(),
        resources.displayMetrics
    ).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(16), dpToPx(16), dpToPx(16), dpToPx(16))
        }

        val title = TextView(this).apply {
            text = getString(R.string.secure_composer_title)
            textSize = 21f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }

        val body = TextView(this).apply {
            text = getString(R.string.secure_composer_placeholder)
        }

        val closeButton = Button(this).apply {
            text = getString(R.string.close_secure_composer)
            setOnClickListener { finish() }
        }

        content.addView(title)
        content.addView(Space(this).apply { minimumHeight = dpToPx(8) })
        content.addView(body)
        content.addView(Space(this).apply { minimumHeight = dpToPx(16) })
        content.addView(closeButton)

        setContentView(content)
    }
}
