package org.cipherboard.cryptocore

internal const val WIRE_VERSION = 1
internal const val MAX_WIRE_BYTES = 8 * 1024 * 1024

internal class CborWriter(
    initialCapacity: Int = 256,
    private val maximum: Int = MAX_WIRE_BYTES,
) : AutoCloseable {
    private var buffer = ByteArray(initialCapacity.coerceAtLeast(16))
    private var position = 0
    private var closed = false

    fun array(size: Int): CborWriter {
        require(size >= 0)
        writeHead(4, size.toLong())
        return this
    }

    fun uint(value: Long): CborWriter {
        require(value >= 0)
        writeHead(0, value)
        return this
    }

    fun bytes(value: ByteArray): CborWriter {
        writeHead(2, value.size.toLong())
        ensure(value.size)
        value.copyInto(buffer, position)
        position += value.size
        return this
    }

    fun ascii(value: String): CborWriter {
        require(value.all { it.code in 0..127 })
        return bytes(value.toByteArray(Charsets.US_ASCII))
    }

    fun finish(): ByteArray {
        check(!closed)
        val result = buffer.copyOf(position)
        close()
        return result
    }

    override fun close() {
        if (!closed) {
            buffer.fill(0)
            buffer = ByteArray(0)
            position = 0
            closed = true
        }
    }

    private fun writeHead(major: Int, value: Long) {
        when {
            value < 24 -> writeByte((major shl 5) or value.toInt())
            value <= 0xff -> {
                writeByte((major shl 5) or 24)
                writeByte(value.toInt())
            }
            value <= 0xffff -> {
                writeByte((major shl 5) or 25)
                writeByte((value ushr 8).toInt())
                writeByte(value.toInt())
            }
            value <= 0xffff_ffffL -> {
                writeByte((major shl 5) or 26)
                for (shift in 24 downTo 0 step 8) writeByte((value ushr shift).toInt())
            }
            else -> {
                writeByte((major shl 5) or 27)
                for (shift in 56 downTo 0 step 8) writeByte((value ushr shift).toInt())
            }
        }
    }

    private fun writeByte(value: Int) {
        ensure(1)
        buffer[position++] = value.toByte()
    }

    private fun ensure(extra: Int) {
        check(!closed)
        val required = position.toLong() + extra
        require(required <= maximum)
        if (required > buffer.size) {
            var newSize = buffer.size
            while (newSize < required) {
                newSize = (newSize * 2).coerceAtMost(maximum)
                if (newSize == buffer.size) throw IllegalArgumentException("CBOR size limit")
            }
            val replacement = buffer.copyOf(newSize)
            buffer.fill(0)
            buffer = replacement
        }
    }
}

internal class CborReader(
    private val input: ByteArray,
    private val maximum: Int = MAX_WIRE_BYTES,
) {
    private var position = 0

    init {
        require(input.size <= maximum)
    }

    fun array(expected: Int) {
        require(arrayLength() == expected)
    }

    fun arrayLength(): Int {
        val length = readHead(4)
        require(length <= Int.MAX_VALUE)
        return length.toInt()
    }

    fun uint(): Long = readHead(0)

    fun bytes(limit: Int): ByteArray {
        val length = readHead(2)
        require(length <= limit && length <= remaining())
        val count = length.toInt()
        val result = input.copyOfRange(position, position + count)
        position += count
        return result
    }

    fun ascii(limit: Int): String {
        val bytes = bytes(limit)
        try {
            require(bytes.all { it.toInt() and 0xff <= 127 })
            return bytes.toString(Charsets.US_ASCII)
        } finally {
            bytes.fill(0)
        }
    }

    fun finish() {
        require(position == input.size)
    }

    private fun readHead(expectedMajor: Int): Long {
        val first = readByte()
        require(first ushr 5 == expectedMajor)
        return when (val additional = first and 0x1f) {
            in 0..23 -> additional.toLong()
            24 -> readUnsigned(1).also { require(it >= 24) }
            25 -> readUnsigned(2).also { require(it > 0xff) }
            26 -> readUnsigned(4).also { require(it > 0xffff) }
            27 -> readUnsigned(8).also { require(it > 0xffff_ffffL) }
            else -> throw IllegalArgumentException("Indefinite CBOR is forbidden")
        }
    }

    private fun readUnsigned(count: Int): Long {
        require(count <= remaining())
        var value = 0L
        repeat(count) {
            val next = readByte()
            if (count == 8 && it == 0) require(next and 0x80 == 0)
            value = (value shl 8) or next.toLong()
        }
        return value
    }

    private fun readByte(): Int {
        require(position < input.size)
        return input[position++].toInt() and 0xff
    }

    private fun remaining(): Int = input.size - position
}
