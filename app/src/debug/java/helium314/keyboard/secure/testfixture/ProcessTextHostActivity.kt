// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.testfixture

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import java.util.concurrent.CountDownLatch

/** Debug-only caller used to verify that PROCESS_TEXT never replaces host text. */
class ProcessTextHostActivity : Activity() {
    val resultLatch = CountDownLatch(1)

    lateinit var editor: EditText
        private set

    @Volatile
    var returnedResultCode: Int = Int.MIN_VALUE
        private set

    @Volatile
    var returnedData: Intent? = null
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        editor = EditText(this).apply {
            setText(intent.getStringExtra(EXTRA_HOST_TEXT).orEmpty())
            inputType = EditorInfo.TYPE_CLASS_TEXT or EditorInfo.TYPE_TEXT_FLAG_MULTI_LINE
        }
        setContentView(editor)
    }

    fun launchProcessText(processTextIntent: Intent) {
        @Suppress("DEPRECATION")
        startActivityForResult(processTextIntent, REQUEST_PROCESS_TEXT)
    }

    @Deprecated("Deprecated by Android; retained in this debug-only result contract fixture")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_PROCESS_TEXT) return
        returnedResultCode = resultCode
        returnedData = data
        resultLatch.countDown()
    }

    companion object {
        const val EXTRA_HOST_TEXT = "cipherboard.test.extra.HOST_TEXT"
        private const val REQUEST_PROCESS_TEXT = 41
    }
}
