package org.cipherboard.securestorage

import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

enum class DomainCodecError {
    TOO_LARGE,
    TRUNCATED,
    WRONG_MAGIC,
    UNSUPPORTED_VERSION,
    TOO_MANY_FIELDS,
    DUPLICATE_FIELD,
    NON_CANONICAL_FIELD_ORDER,
    UNKNOWN_REQUIRED_FIELD,
    INVALID_FLAGS,
    WRONG_TYPE,
    FIELD_TOO_LARGE,
    MISSING_REQUIRED_FIELD,
    INVALID_VALUE,
    INVALID_UTF8,
    TRAILING_DATA,
}

class DomainCodecException(
    val reason: DomainCodecError,
    val fieldId: Int? = null,
) : IllegalArgumentException(
    if (fieldId == null) "Invalid Vault record: ${reason.name}"
    else "Invalid Vault record field $fieldId: ${reason.name}",
)

internal enum class BinaryFieldType(val code: Int) {
    BYTES(1),
    UTF8(2),
    U32(3),
    U64(4),
    BOOLEAN(5),
    ENUM(6),
}

internal data class BinaryFieldSpec(
    val id: Int,
    val type: BinaryFieldType,
    val required: Boolean = true,
    val maxBytes: Int,
)

internal data class BinaryField(
    val spec: BinaryFieldSpec,
    val value: ByteArray,
)

internal object StrictBinaryCodec {
    private const val HEADER_BYTES = 8
    private const val FIELD_HEADER_BYTES = 8
    private const val REQUIRED_FLAG = 1
    private const val MAX_FIELDS = 64

    fun encode(
        magic: Int,
        version: Int,
        maxRecordBytes: Int,
        fields: List<BinaryField>,
    ): ByteArray {
        require(version in 1..0xffff)
        require(fields.size in 1..MAX_FIELDS)
        val sorted = fields.sortedBy { it.spec.id }
        var previous = 0
        var total = HEADER_BYTES
        sorted.forEach { field ->
            require(field.spec.id in 1..0xffff && field.spec.id > previous)
            require(field.value.size <= field.spec.maxBytes)
            previous = field.spec.id
            total = Math.addExact(total, Math.addExact(FIELD_HEADER_BYTES, field.value.size))
            if (total > maxRecordBytes) throw DomainCodecException(DomainCodecError.TOO_LARGE)
        }
        val output = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        output.putInt(magic)
        output.putShort(version.toShort())
        output.putShort(sorted.size.toShort())
        sorted.forEach { field ->
            output.putShort(field.spec.id.toShort())
            output.put(if (field.spec.required) REQUIRED_FLAG.toByte() else 0.toByte())
            output.put(field.spec.type.code.toByte())
            output.putInt(field.value.size)
            output.put(field.value)
        }
        return output.array()
    }

    fun decode(
        encoded: ByteArray,
        magic: Int,
        version: Int,
        maxRecordBytes: Int,
        specs: List<BinaryFieldSpec>,
    ): DecodedBinaryFields {
        if (encoded.size > maxRecordBytes) throw DomainCodecException(DomainCodecError.TOO_LARGE)
        if (encoded.size < HEADER_BYTES) throw DomainCodecException(DomainCodecError.TRUNCATED)
        val specById = specs.associateBy { it.id }
        require(specById.size == specs.size)
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        if (buffer.int != magic) throw DomainCodecException(DomainCodecError.WRONG_MAGIC)
        if (buffer.short.toInt() and 0xffff != version) {
            throw DomainCodecException(DomainCodecError.UNSUPPORTED_VERSION)
        }
        val fieldCount = buffer.short.toInt() and 0xffff
        if (fieldCount > MAX_FIELDS) throw DomainCodecException(DomainCodecError.TOO_MANY_FIELDS)
        if (fieldCount > buffer.remaining() / FIELD_HEADER_BYTES) {
            throw DomainCodecException(DomainCodecError.TRUNCATED)
        }
        val values = HashMap<Int, Pair<BinaryFieldType, ByteArray>>(fieldCount)
        var previousId = 0
        try {
            repeat(fieldCount) {
                if (buffer.remaining() < FIELD_HEADER_BYTES) throw DomainCodecException(DomainCodecError.TRUNCATED)
                val id = buffer.short.toInt() and 0xffff
                val flags = buffer.get().toInt() and 0xff
                val typeCode = buffer.get().toInt() and 0xff
                val length = buffer.int
                if (flags and REQUIRED_FLAG.inv() != 0) {
                    throw DomainCodecException(DomainCodecError.INVALID_FLAGS, id)
                }
                if (id == previousId) throw DomainCodecException(DomainCodecError.DUPLICATE_FIELD, id)
                if (id < previousId || id == 0) {
                    throw DomainCodecException(DomainCodecError.NON_CANONICAL_FIELD_ORDER, id)
                }
                previousId = id
                if (length < 0 || length > buffer.remaining()) {
                    throw DomainCodecException(DomainCodecError.TRUNCATED, id)
                }
                val spec = specById[id]
                if (spec == null) {
                    if (flags and REQUIRED_FLAG != 0) {
                        throw DomainCodecException(DomainCodecError.UNKNOWN_REQUIRED_FIELD, id)
                    }
                    buffer.position(buffer.position() + length)
                    return@repeat
                }
                if ((flags and REQUIRED_FLAG != 0) != spec.required) {
                    throw DomainCodecException(DomainCodecError.INVALID_FLAGS, id)
                }
                if (typeCode != spec.type.code) throw DomainCodecException(DomainCodecError.WRONG_TYPE, id)
                if (length > spec.maxBytes) throw DomainCodecException(DomainCodecError.FIELD_TOO_LARGE, id)
                val value = ByteArray(length)
                buffer.get(value)
                values[id] = spec.type to value
            }
            if (buffer.hasRemaining()) throw DomainCodecException(DomainCodecError.TRAILING_DATA)
            specs.filter { it.required }.forEach { spec ->
                if (!values.containsKey(spec.id)) {
                    throw DomainCodecException(DomainCodecError.MISSING_REQUIRED_FIELD, spec.id)
                }
            }
            return DecodedBinaryFields(values)
        } catch (e: Exception) {
            values.values.forEach { it.second.wipe() }
            throw e
        }
    }

    fun bytes(spec: BinaryFieldSpec, value: ByteArray) = BinaryField(spec, value.copyOf())
    fun utf8(spec: BinaryFieldSpec, value: String) = BinaryField(spec, value.toByteArray(StandardCharsets.UTF_8))
    fun u32(spec: BinaryFieldSpec, value: Int): BinaryField {
        if (value < 0) throw DomainCodecException(DomainCodecError.INVALID_VALUE, spec.id)
        return BinaryField(spec, ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array())
    }
    fun u64(spec: BinaryFieldSpec, value: Long): BinaryField {
        if (value < 0) throw DomainCodecException(DomainCodecError.INVALID_VALUE, spec.id)
        return BinaryField(spec, ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(value).array())
    }
    fun bool(spec: BinaryFieldSpec, value: Boolean) = BinaryField(spec, byteArrayOf(if (value) 1 else 0))
    fun enum(spec: BinaryFieldSpec, value: Int) = u32(spec, value)

    fun wipeFields(fields: List<BinaryField>) = fields.forEach { it.value.wipe() }
}

internal class DecodedBinaryFields(
    private val values: MutableMap<Int, Pair<BinaryFieldType, ByteArray>>,
) : Closeable {
    fun takeBytes(id: Int): ByteArray = values.remove(id)?.second
        ?: throw DomainCodecException(DomainCodecError.MISSING_REQUIRED_FIELD, id)

    fun utf8(id: Int): String {
        val bytes = takeBytes(id)
        return try {
            try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString()
            } catch (_: Exception) {
                throw DomainCodecException(DomainCodecError.INVALID_UTF8, id)
            }
        } finally {
            bytes.wipe()
        }
    }

    fun u32(id: Int): Int {
        val bytes = takeBytes(id)
        return try {
            if (bytes.size != 4) throw DomainCodecException(DomainCodecError.INVALID_VALUE, id)
            val value = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).int
            if (value < 0) throw DomainCodecException(DomainCodecError.INVALID_VALUE, id)
            value
        } finally {
            bytes.wipe()
        }
    }

    fun u64(id: Int): Long {
        val bytes = takeBytes(id)
        return try {
            if (bytes.size != 8) throw DomainCodecException(DomainCodecError.INVALID_VALUE, id)
            val value = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).long
            if (value < 0) throw DomainCodecException(DomainCodecError.INVALID_VALUE, id)
            value
        } finally {
            bytes.wipe()
        }
    }

    fun bool(id: Int): Boolean {
        val bytes = takeBytes(id)
        return try {
            if (bytes.size != 1 || bytes[0].toInt() !in 0..1) {
                throw DomainCodecException(DomainCodecError.INVALID_VALUE, id)
            }
            bytes[0].toInt() == 1
        } finally {
            bytes.wipe()
        }
    }

    fun enum(id: Int): Int = u32(id)

    override fun close() {
        values.values.forEach { it.second.wipe() }
        values.clear()
    }
}
