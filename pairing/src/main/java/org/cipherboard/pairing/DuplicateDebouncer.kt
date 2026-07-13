package org.cipherboard.pairing

import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal class DuplicateDebouncer(
    private val debounceMillis: Long,
) : Closeable {
    private var lastDigest: ByteArray? = null
    private var lastDeliveryMillis: Long = Long.MIN_VALUE

    init {
        require(debounceMillis >= 0)
    }

    @Synchronized
    fun shouldDeliver(payload: PairingQrPayload, nowMillis: Long): Boolean {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(payload.value.toByteArray(StandardCharsets.US_ASCII))
        val previous = lastDigest
        val elapsed = if (nowMillis >= lastDeliveryMillis) nowMillis - lastDeliveryMillis else Long.MAX_VALUE
        if (previous != null && previous.contentEquals(digest) && elapsed < debounceMillis) {
            digest.fill(0)
            return false
        }
        previous?.fill(0)
        lastDigest = digest
        lastDeliveryMillis = nowMillis
        return true
    }

    @Synchronized
    override fun close() {
        lastDigest?.fill(0)
        lastDigest = null
        lastDeliveryMillis = Long.MIN_VALUE
    }
}
