package org.cipherboard.securestorage

import java.nio.ByteBuffer

internal object PendingRecordCodec {
    fun encodedSize(identifier: ByteArray, payloadSize: Int): Int {
        require(identifier.size in MIN_ID_BYTES..MAX_ID_BYTES)
        require(payloadSize >= 0)
        require(payloadSize <= RecordCrypto.MAX_RECORD_BYTES - HEADER_BYTES - identifier.size)
        return Math.addExact(Math.addExact(HEADER_BYTES, identifier.size), payloadSize)
    }

    fun encode(identifier: ByteArray, payload: ByteArray): ByteArray {
        return ByteBuffer.allocate(encodedSize(identifier, payload.size))
            .putInt(FORMAT_VERSION)
            .putInt(identifier.size)
            .put(identifier)
            .putInt(payload.size)
            .put(payload)
            .array()
    }

    @Throws(VaultCorruptException::class)
    fun decode(encoded: ByteArray): Pair<ByteArray, ByteArray> {
        try {
            if (encoded.size < HEADER_BYTES) throw VaultCorruptException("Pending record is truncated")
            val buffer = ByteBuffer.wrap(encoded)
            if (buffer.int != FORMAT_VERSION) throw VaultCorruptException("Unknown pending record version")
            val idSize = buffer.int
            if (idSize !in MIN_ID_BYTES..MAX_ID_BYTES || idSize > buffer.remaining() - Int.SIZE_BYTES) {
                throw VaultCorruptException("Invalid pending record identifier")
            }
            val id = ByteArray(idSize).also(buffer::get)
            val payloadSize = buffer.int
            if (payloadSize < 0 || payloadSize != buffer.remaining()) {
                id.wipe()
                throw VaultCorruptException("Invalid pending record payload")
            }
            val payload = ByteArray(payloadSize).also(buffer::get)
            return id to payload
        } catch (e: VaultCorruptException) {
            throw e
        } catch (e: RuntimeException) {
            throw VaultCorruptException("Cannot parse pending record", e)
        }
    }

    private const val FORMAT_VERSION = 1
    private const val MIN_ID_BYTES = 8
    private const val MAX_ID_BYTES = 128
    private const val HEADER_BYTES = Int.SIZE_BYTES * 3
}
