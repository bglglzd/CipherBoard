// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VerificationSnapshotTest {
    @Test
    fun displayedFingerprintAndSafetyCodesMustAllMatchCurrentRecord() {
        val fingerprint = ByteArray(32) { it.toByte() }
        val displayed = fingerprint.joinToString("") { "%02X".format(it.toInt() and 0xff) }
            .chunked(8)
            .joinToString(" ")
        assertTrue(
            verificationSnapshotMatches(
                fingerprint,
                "12345 67890",
                "amber beacon",
                displayed,
                "12345 67890",
                "amber beacon",
            ),
        )
        assertFalse(
            verificationSnapshotMatches(
                fingerprint,
                "12345 67890",
                "amber beacon",
                displayed.replaceFirst('0', 'F'),
                "12345 67890",
                "amber beacon",
            ),
        )
        assertFalse(
            verificationSnapshotMatches(
                fingerprint,
                "12345 67890",
                "amber beacon",
                displayed,
                "12345 67891",
                "amber beacon",
            ),
        )
    }
}
