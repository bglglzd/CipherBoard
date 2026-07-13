package org.cipherboard.securestorage

import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

internal fun ByteArray.wipe() {
    fill(0)
}

/** A single-owner secret buffer. [take] transfers ownership and may be called once. */
class OwnedSecret internal constructor(secret: ByteArray) : Closeable {
    private val closed = AtomicBoolean(false)
    private var bytes: ByteArray? = secret

    val size: Int
        get() = synchronized(this) { bytes?.size ?: 0 }

    internal fun take(): ByteArray = synchronized(this) {
        check(!closed.get()) { "Secret is closed" }
        val value = checkNotNull(bytes) { "Secret ownership was already transferred" }
        bytes = null
        closed.set(true)
        value
    }

    /** Runs [block] once, then overwrites the transferred buffer even if [block] throws. */
    fun <T> consume(block: (ByteArray) -> T): T {
        val value = take()
        return try {
            block(value)
        } finally {
            value.wipe()
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        synchronized(this) {
            bytes?.wipe()
            bytes = null
        }
    }

    companion object {
        /** Transfers ownership; callers must not access [secret] after this call. */
        fun takeOwnership(secret: ByteArray): OwnedSecret = OwnedSecret(secret)
    }
}
