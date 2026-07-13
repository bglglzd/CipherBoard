package org.cipherboard.securestorage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultLockControllerTest {
    @Test
    fun defaultPolicyLocksOneMinuteAfterBackground() {
        val clock = FakeClock()
        val source = ByteArray(32) { 0x5a }
        val controller = VaultLockController(clock = clock)
        controller.unlock(material(source))

        controller.onBackgrounded()
        clock.now = 59_999
        assertTrue(controller.isUnlocked())
        clock.now = 60_000
        assertFalse(controller.isUnlocked())
        assertTrue(source.all { it == 0.toByte() })
    }

    @Test
    fun screenLockAndManualLockWipeImmediately() {
        val first = ByteArray(32) { 1 }
        val second = ByteArray(32) { 2 }
        val controller = VaultLockController(clock = FakeClock())

        controller.unlock(material(first))
        controller.onScreenLocked()
        assertFalse(controller.isUnlocked())
        assertTrue(first.all { it == 0.toByte() })

        controller.unlock(material(second))
        controller.lock()
        assertTrue(second.all { it == 0.toByte() })
        assertThrows(VaultLockedException::class.java) {
            controller.withDek { error("must not run") }
        }
    }

    @Test
    fun immediatePolicyLocksOnBackground() {
        val controller = VaultLockController(VaultLockPolicy.IMMEDIATE, FakeClock())
        controller.unlock(material(ByteArray(32)))
        controller.onBackgrounded()
        assertFalse(controller.isUnlocked())
    }

    private fun material(bytes: ByteArray) = UnlockedVaultMaterial(
        KeyProtectionInfo(
            KeystoreSecurityLevel.TRUSTED_ENVIRONMENT,
            strongBoxAttempted = true,
            strongBoxGenerationSucceeded = false,
            VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL,
        ),
        OwnedSecret(bytes),
    )

    private class FakeClock(var now: Long = 0) : MonotonicClock {
        override fun nowMillis(): Long = now
    }
}
