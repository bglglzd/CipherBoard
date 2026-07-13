package org.cipherboard.cryptocore

/**
 * Explicit owner of a sensitive byte array.
 *
 * The supplied array is taken without copying. References passed to [use]
 * must not escape the callback. JVM and Android UI internals prevent absolute
 * guarantees that every historical memory copy can be erased.
 */
class OwnedSecret private constructor(private var value: ByteArray) : AutoCloseable {
    private var cleared = false

    val size: Int
        get() = if (cleared) 0 else value.size

    val isCleared: Boolean
        get() = cleared

    fun <T> use(block: (ByteArray) -> T): T {
        check(!cleared) { "Secret has been cleared" }
        return block(value)
    }

    fun clear() {
        if (!cleared) {
            value.fill(0)
            value = EMPTY
            cleared = true
        }
    }

    override fun close() = clear()

    override fun toString(): String = "OwnedSecret(size=$size, cleared=$cleared)"

    companion object {
        private val EMPTY = ByteArray(0)

        /** Transfer ownership of [bytes] to a zeroizing container. */
        fun takeOwnership(bytes: ByteArray): OwnedSecret = OwnedSecret(bytes)
    }
}
