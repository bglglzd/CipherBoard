package org.cipherboard.securestorage

import android.os.SystemClock
import java.io.Closeable
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

enum class VaultLockPolicy(val backgroundTimeoutMillis: Long) {
    IMMEDIATE(0),
    THIRTY_SECONDS(30_000),
    ONE_MINUTE(60_000),
    FIVE_MINUTES(300_000),
}

fun interface MonotonicClock {
    fun nowMillis(): Long
}

fun interface ScheduledVaultLock : Closeable {
    override fun close()
}

fun interface VaultLockScheduler {
    fun schedule(delayMillis: Long, action: () -> Unit): ScheduledVaultLock
}

private object ProcessVaultLockScheduler : VaultLockScheduler {
    private val executor = ScheduledThreadPoolExecutor(1) { runnable ->
        Thread(runnable, "CipherBoard-VaultLock").apply { isDaemon = true }
    }.apply {
        removeOnCancelPolicy = true
        setExecuteExistingDelayedTasksAfterShutdownPolicy(false)
        setContinueExistingPeriodicTasksAfterShutdownPolicy(false)
    }

    override fun schedule(delayMillis: Long, action: () -> Unit): ScheduledVaultLock {
        val future = executor.schedule(action, delayMillis, TimeUnit.MILLISECONDS)
        return ScheduledVaultLock { future.cancel(false) }
    }
}

/**
 * Owns the only long-lived in-memory DEK. Timeouts start when the app/IME goes to background;
 * screen lock, reboot restoration and explicit lock always wipe immediately.
 *
 * The scheduled wipe is best-effort while Android freezes this process. Expiration is also checked
 * synchronously on every vault access and foreground transition, so a delayed callback cannot make
 * an expired DEK usable after the process resumes.
 */
class VaultLockController(
    var policy: VaultLockPolicy = VaultLockPolicy.ONE_MINUTE,
    private val clock: MonotonicClock = MonotonicClock { SystemClock.elapsedRealtime() },
    private val scheduler: VaultLockScheduler = ProcessVaultLockScheduler,
) : Closeable {
    private var dek: ByteArray? = null
    private var lockDeadlineMillis: Long? = null
    private var scheduledLock: ScheduledVaultLock? = null
    private var freshAuthenticationRequired = true

    @Synchronized
    fun unlock(material: UnlockedVaultMaterial) {
        lockInternal(requireFreshAuthentication = false)
        dek = material.transferDek()
        lockDeadlineMillis = null
        freshAuthenticationRequired = false
    }

    @Synchronized
    fun requiresFreshAuthentication(): Boolean = freshAuthenticationRequired

    @Synchronized
    fun isUnlocked(): Boolean {
        lockIfExpiredInternal()
        return dek != null
    }

    @Synchronized
    fun onBackgrounded() {
        if (dek == null) return
        if (policy == VaultLockPolicy.IMMEDIATE) {
            lockInternal()
        } else {
            val now = clock.nowMillis()
            val candidate = safeDeadline(now, policy.backgroundTimeoutMillis)
            val current = lockDeadlineMillis
            if (current == null || candidate < current) {
                lockDeadlineMillis = candidate
                scheduleLockInternal(candidate, now)
            }
        }
    }

    @Synchronized
    fun onForegrounded(): Boolean {
        lockIfExpiredInternal()
        val unlocked = dek != null
        if (unlocked) cancelDeadlineInternal()
        return unlocked
    }

    @Synchronized
    fun lockIfExpired(): Boolean {
        val wasUnlocked = dek != null
        lockIfExpiredInternal()
        return wasUnlocked && dek == null
    }

    @Synchronized
    fun onScreenLocked() = lockInternal()

    @Synchronized
    fun onBootBoundary() = lockInternal()

    @Synchronized
    fun onKeystoreInvalidated() = lockInternal()

    @Synchronized
    fun lock() = lockInternal()

    @Synchronized
    internal fun <T> withDek(block: (ByteArray) -> T): T {
        lockIfExpiredInternal()
        val current = dek ?: throw VaultLockedException()
        return block(current)
    }

    override fun close() = lock()

    private fun lockIfExpiredInternal() {
        val deadline = lockDeadlineMillis ?: return
        if (clock.nowMillis() >= deadline) lockInternal()
    }

    @Synchronized
    private fun onScheduledLock(deadline: Long) {
        if (lockDeadlineMillis != deadline) return
        scheduledLock = null
        val now = clock.nowMillis()
        if (now >= deadline) {
            lockInternal()
        } else {
            // A scheduler is permitted to wake early; preserve the original monotonic deadline.
            scheduleLockInternal(deadline, now)
        }
    }

    private fun scheduleLockInternal(deadline: Long, now: Long) {
        scheduledLock?.close()
        scheduledLock = try {
            scheduler.schedule(safeDelay(deadline, now)) { onScheduledLock(deadline) }
        } catch (_: RuntimeException) {
            // Synchronous expiration checks remain authoritative if scheduling is unavailable.
            null
        }
    }

    private fun cancelDeadlineInternal() {
        scheduledLock?.close()
        scheduledLock = null
        lockDeadlineMillis = null
    }

    private fun lockInternal(requireFreshAuthentication: Boolean = true) {
        dek?.wipe()
        dek = null
        if (requireFreshAuthentication) freshAuthenticationRequired = true
        cancelDeadlineInternal()
    }

    private fun safeDeadline(now: Long, timeout: Long): Long =
        if (Long.MAX_VALUE - now < timeout) Long.MAX_VALUE else now + timeout

    private fun safeDelay(deadline: Long, now: Long): Long {
        if (deadline <= now) return 0
        val delay = deadline - now
        return if (delay < 0) Long.MAX_VALUE else delay
    }
}
