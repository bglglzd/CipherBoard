package org.cipherboard.securestorage

import android.os.SystemClock
import java.io.Closeable

enum class VaultLockPolicy(val backgroundTimeoutMillis: Long) {
    IMMEDIATE(0),
    THIRTY_SECONDS(30_000),
    ONE_MINUTE(60_000),
    FIVE_MINUTES(300_000),
}

fun interface MonotonicClock {
    fun nowMillis(): Long
}

/**
 * Owns the only long-lived in-memory DEK. Timeouts start when the app/IME goes to background;
 * screen lock, reboot restoration and explicit lock always wipe immediately.
 */
class VaultLockController(
    var policy: VaultLockPolicy = VaultLockPolicy.ONE_MINUTE,
    private val clock: MonotonicClock = MonotonicClock { SystemClock.elapsedRealtime() },
) : Closeable {
    private var dek: ByteArray? = null
    private var lockDeadlineMillis: Long? = null

    @Synchronized
    fun unlock(material: UnlockedVaultMaterial) {
        lockInternal()
        dek = material.transferDek()
        lockDeadlineMillis = null
    }

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
            lockDeadlineMillis = safeDeadline(clock.nowMillis(), policy.backgroundTimeoutMillis)
        }
    }

    @Synchronized
    fun onForegrounded(): Boolean {
        lockIfExpiredInternal()
        val unlocked = dek != null
        if (unlocked) lockDeadlineMillis = null
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

    private fun lockInternal() {
        dek?.wipe()
        dek = null
        lockDeadlineMillis = null
    }

    private fun safeDeadline(now: Long, timeout: Long): Long =
        if (Long.MAX_VALUE - now < timeout) Long.MAX_VALUE else now + timeout
}
