// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast

/** Minimal local-only trampoline used because an InputMethodService cannot show a permission UI. */
class OfflineVoicePermissionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            notifyKeyboardAndFinish(granted = true)
        } else {
            requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO), REQUEST_MICROPHONE)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_MICROPHONE &&
            grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED
        ) {
            notifyKeyboardAndFinish(granted = true)
        } else {
            Toast.makeText(this, R.string.offline_voice_permission_denied, Toast.LENGTH_LONG).show()
            notifyKeyboardAndFinish(granted = false)
        }
    }

    private fun notifyKeyboardAndFinish(granted: Boolean) {
        finish()
        sendBroadcast(
            Intent(ACTION_PERMISSION_RESULT)
                .setPackage(packageName)
                .putExtra(EXTRA_GRANTED, granted),
        )
    }

    companion object {
        const val ACTION_PERMISSION_RESULT =
            BuildConfig.APPLICATION_ID + ".action.OFFLINE_VOICE_PERMISSION_RESULT"
        const val EXTRA_GRANTED = BuildConfig.APPLICATION_ID + ".extra.OFFLINE_VOICE_PERMISSION_GRANTED"
        private const val REQUEST_MICROPHONE = 801
    }
}
