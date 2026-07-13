// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure.home

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlin.test.Test
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class OfflineLicenseAssetsTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun everyRequiredLicenseDocumentIsPackagedAndReadableOffline() {
        val required = listOf(
            "LICENSE",
            "LICENSES.md",
            "THIRD_PARTY_NOTICES.md",
            "UPSTREAM.md",
            "LICENSE-Apache-2.0",
            "LICENSE-BlueOak-1.0.0",
            "LICENSE-BSD-3-Clause-NOTICES",
            "LICENSE-CC-BY-SA-4.0",
        )

        required.forEach { name ->
            val text = context.assets.open("licenses/$name").bufferedReader(Charsets.UTF_8).use { it.readText() }
            assertTrue(text.isNotBlank(), "Missing or empty offline license asset: $name")
        }
    }
}
