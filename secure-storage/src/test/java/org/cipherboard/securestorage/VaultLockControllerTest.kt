package org.cipherboard.securestorage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultLockControllerTest {
    @Test
    fun defaultPolicyLocksOneMinuteAfterBackground() {
        val clock = FakeClock()
        val scheduler = FakeScheduler(clock)
        val source = ByteArray(32) { 0x5a }
        val controller = VaultLockController(clock = clock, scheduler = scheduler)
        controller.unlock(material(source))

        controller.onBackgrounded()
        scheduler.advanceTo(59_999)
        assertTrue(controller.isUnlocked())
        scheduler.advanceTo(60_000)
        assertFalse(controller.isUnlocked())
        assertTrue(source.all { it == 0.toByte() })
    }

    @Test
    fun scheduledCallbackWipesWithoutAnotherVaultAccess() {
        val clock = FakeClock()
        val scheduler = FakeScheduler(clock)
        val source = ByteArray(32) { 0x31 }
        val controller = VaultLockController(clock = clock, scheduler = scheduler)
        controller.unlock(material(source))

        controller.onBackgrounded()
        scheduler.advanceTo(60_000)

        assertTrue(source.all { it == 0.toByte() })
        assertEquals(1, scheduler.executedTaskCount)
    }

    @Test
    fun repeatedBackgroundKeepsEarliestDeadline() {
        val clock = FakeClock()
        val scheduler = FakeScheduler(clock)
        val source = ByteArray(32) { 0x32 }
        val controller = VaultLockController(clock = clock, scheduler = scheduler)
        controller.unlock(material(source))

        controller.onBackgrounded()
        scheduler.advanceTo(20_000)
        controller.onBackgrounded()
        scheduler.advanceTo(59_999)
        assertFalse(source.all { it == 0.toByte() })

        scheduler.advanceTo(60_000)
        assertTrue(source.all { it == 0.toByte() })
        assertEquals(1, scheduler.scheduledTaskCount)
    }

    @Test
    fun shorterPolicyMovesDeadlineEarlier() {
        val clock = FakeClock()
        val scheduler = FakeScheduler(clock)
        val source = ByteArray(32) { 0x33 }
        val controller = VaultLockController(clock = clock, scheduler = scheduler)
        controller.unlock(material(source))

        controller.onBackgrounded()
        scheduler.advanceTo(10_000)
        controller.policy = VaultLockPolicy.THIRTY_SECONDS
        controller.onBackgrounded()
        scheduler.advanceTo(39_999)
        assertFalse(source.all { it == 0.toByte() })

        scheduler.advanceTo(40_000)
        assertTrue(source.all { it == 0.toByte() })
    }

    @Test
    fun foregroundCancelsScheduledWipe() {
        val clock = FakeClock()
        val scheduler = FakeScheduler(clock)
        val source = ByteArray(32) { 0x34 }
        val controller = VaultLockController(clock = clock, scheduler = scheduler)
        controller.unlock(material(source))

        controller.onBackgrounded()
        scheduler.advanceTo(30_000)
        assertTrue(controller.onForegrounded())
        scheduler.advanceTo(90_000)

        assertFalse(source.all { it == 0.toByte() })
        assertTrue(controller.isUnlocked())
        assertEquals(1, scheduler.cancelledTaskCount)
    }

    @Test
    fun screenLockAndManualLockWipeImmediately() {
        val clock = FakeClock()
        val scheduler = FakeScheduler(clock)
        val first = ByteArray(32) { 1 }
        val second = ByteArray(32) { 2 }
        val controller = VaultLockController(clock = clock, scheduler = scheduler)

        controller.unlock(material(first))
        assertFalse(controller.requiresFreshAuthentication())
        controller.onBackgrounded()
        controller.onScreenLocked()
        assertFalse(controller.isUnlocked())
        assertTrue(controller.requiresFreshAuthentication())
        assertTrue(first.all { it == 0.toByte() })
        assertEquals(1, scheduler.cancelledTaskCount)

        controller.unlock(material(second))
        assertFalse(controller.requiresFreshAuthentication())
        controller.onBackgrounded()
        controller.lock()
        assertTrue(controller.requiresFreshAuthentication())
        assertTrue(second.all { it == 0.toByte() })
        assertEquals(2, scheduler.cancelledTaskCount)
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

    private class FakeScheduler(private val clock: FakeClock) : VaultLockScheduler {
        private data class Task(
            val deadline: Long,
            val action: () -> Unit,
            var cancelled: Boolean = false,
            var executed: Boolean = false,
        )

        private val tasks = mutableListOf<Task>()
        val scheduledTaskCount: Int get() = tasks.size
        val cancelledTaskCount: Int get() = tasks.count { it.cancelled }
        val executedTaskCount: Int get() = tasks.count { it.executed }

        override fun schedule(delayMillis: Long, action: () -> Unit): ScheduledVaultLock {
            val task = Task(clock.now + delayMillis, action)
            tasks += task
            return ScheduledVaultLock { task.cancelled = true }
        }

        fun advanceTo(target: Long) {
            require(target >= clock.now)
            while (true) {
                val next = tasks
                    .filter { !it.cancelled && !it.executed && it.deadline <= target }
                    .minByOrNull { it.deadline }
                    ?: break
                clock.now = next.deadline
                next.executed = true
                next.action()
            }
            clock.now = target
        }
    }
}
