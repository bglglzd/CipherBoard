// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SecurityManifestTest {
    private val forbiddenPermissions = setOf(
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    )

    @Suppress("DEPRECATION")
    @Test
    fun mergedManifestHasNoForbiddenPermissions() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val packageInfo = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        val requested = packageInfo.requestedPermissions.orEmpty().toSet()

        assertTrue(
            requested.intersect(forbiddenPermissions).isEmpty(),
            "Forbidden permissions: ${requested.intersect(forbiddenPermissions).sorted()}",
        )
    }

    @Suppress("DEPRECATION")
    @Test
    fun backupAndCleartextTrafficAreDisabled() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val info = context.applicationInfo

        assertFalse(info.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0)
        assertFalse(info.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0)
    }
}
