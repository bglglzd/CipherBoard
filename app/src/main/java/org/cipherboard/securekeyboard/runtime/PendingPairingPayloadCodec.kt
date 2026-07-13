// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import org.cipherboard.pairing.PairingQrPayload
import org.cipherboard.pairing.PairingQrPayloadType
import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal enum class PendingPairingRole(val wire: Int) {
    OFFERER(1),
    RESPONDER(2),
    ;

    companion object {
        fun fromWire(value: Int): PendingPairingRole = entries.firstOrNull { it.wire == value }
            ?: throw IllegalArgumentException("Invalid pending pairing role")
    }
}

/** Secret session bytes are present only for a responder record. */
internal class PendingPairingPayload(
    val role: PendingPairingRole,
    val replacingExistingContact: Boolean,
    val requestedCapabilities: Long,
    contactId: ByteArray,
    val localContactName: String,
    offerQr: ByteArray,
    responseQr: ByteArray,
    sessionState: ByteArray,
    remoteFingerprint: ByteArray,
    routingTag: ByteArray,
    val safetyNumber: String,
    val safetyCode: String,
) : Closeable {
    val contactId: ByteArray
    val offerQr: ByteArray
    val responseQr: ByteArray
    val sessionState: ByteArray
    val remoteFingerprint: ByteArray
    val routingTag: ByteArray

    init {
        require(requestedCapabilities in 0..MAX_CAPABILITIES)
        require(contactId.size == CONTACT_ID_BYTES)
        require(localContactName.isNotBlank())
        require(localContactName.codePointCount(0, localContactName.length) <= 128)
        require(localContactName.none { it == '\u0000' || it == '\r' || it == '\n' || Character.isISOControl(it) })
        val encodedName = localContactName.toByteArray(StandardCharsets.UTF_8)
        try {
            require(encodedName.size <= MAX_NAME_BYTES)
        } finally {
            encodedName.fill(0)
        }
        requireQr(offerQr, PairingQrPayloadType.OFFER)
        when (role) {
            PendingPairingRole.OFFERER -> {
                require(responseQr.isEmpty())
                require(sessionState.isEmpty())
                require(remoteFingerprint.isEmpty())
                require(routingTag.isEmpty())
                require(safetyNumber.isEmpty() && safetyCode.isEmpty())
            }
            PendingPairingRole.RESPONDER -> {
                requireQr(responseQr, PairingQrPayloadType.RESPONSE)
                require(sessionState.size in 1..MAX_SESSION_BYTES)
                require(remoteFingerprint.size == FINGERPRINT_BYTES)
                require(routingTag.size == ROUTING_TAG_BYTES)
                requireSafetyNumber(safetyNumber)
                requireSafetyCode(safetyCode)
            }
        }
        this.contactId = contactId.copyOf()
        this.offerQr = offerQr.copyOf()
        this.responseQr = responseQr.copyOf()
        this.sessionState = sessionState.copyOf()
        this.remoteFingerprint = remoteFingerprint.copyOf()
        this.routingTag = routingTag.copyOf()
    }

    override fun close() {
        contactId.fill(0)
        offerQr.fill(0)
        responseQr.fill(0)
        sessionState.fill(0)
        remoteFingerprint.fill(0)
        routingTag.fill(0)
    }

    override fun toString(): String = "PendingPairingPayload(role=$role,redacted)"

    companion object {
        const val CONTACT_ID_BYTES = 16
        const val FINGERPRINT_BYTES = 32
        const val ROUTING_TAG_BYTES = 16
        const val MAX_NAME_BYTES = 512
        const val MAX_QR_BYTES = 32 * 1024
        const val MAX_SESSION_BYTES = 448 * 1024
        const val MAX_SAFETY_NUMBER_BYTES = 96
        const val MAX_SAFETY_CODE_BYTES = 128
        const val MAX_CAPABILITIES = 0xffff_ffffL

        private fun requireQr(bytes: ByteArray, expected: PairingQrPayloadType) {
            require(bytes.size in 1..MAX_QR_BYTES)
            require(bytes.all { it.toInt() and 0xff in 0x21..0x7e })
            val parsed = PairingQrPayload.parse(String(bytes, StandardCharsets.US_ASCII))
            require(parsed.type == expected)
        }

        private fun requireSafetyNumber(value: String) {
            require(value.length in 1..MAX_SAFETY_NUMBER_BYTES)
            require(value.first().isDigit() && value.last().isDigit())
            require(value.all { it in '0'..'9' || it == ' ' } && "  " !in value)
        }

        private fun requireSafetyCode(value: String) {
            require(value.length in 1..MAX_SAFETY_CODE_BYTES)
            require(value.first() != ' ' && value.last() != ' ')
            require(value.all { it.code in 0x21..0x7e || it == ' ' } && "  " !in value)
        }
    }
}

internal object PendingPairingPayloadCodec {
    private const val MAGIC = 0x43425052
    private const val VERSION = 2
    private const val FIELD_COUNT = 9
    private const val FIXED_BYTES = 4 + 1 + 1 + 1 + Long.SIZE_BYTES + FIELD_COUNT * 4

    fun encode(value: PendingPairingPayload): ByteArray {
        val name = value.localContactName.toByteArray(StandardCharsets.UTF_8)
        val safetyNumber = value.safetyNumber.toByteArray(StandardCharsets.US_ASCII)
        val safetyCode = value.safetyCode.toByteArray(StandardCharsets.US_ASCII)
        return try {
            val fields = arrayOf(
                value.contactId,
                name,
                value.offerQr,
                value.responseQr,
                value.sessionState,
                value.remoteFingerprint,
                value.routingTag,
                safetyNumber,
                safetyCode,
            )
            val size = fields.fold(FIXED_BYTES.toLong()) { total, field -> total + field.size }
            require(size <= MAX_ENCODED_BYTES)
            ByteBuffer.allocate(size.toInt()).order(ByteOrder.BIG_ENDIAN).apply {
                putInt(MAGIC)
                put(VERSION.toByte())
                put(value.role.wire.toByte())
                put(if (value.replacingExistingContact) 1 else 0)
                putLong(value.requestedCapabilities)
                fields.forEach { field ->
                    putInt(field.size)
                    put(field)
                }
            }.array()
        } finally {
            name.fill(0)
            safetyNumber.fill(0)
            safetyCode.fill(0)
        }
    }

    fun decode(encoded: ByteArray): PendingPairingPayload {
        require(encoded.size in FIXED_BYTES..MAX_ENCODED_BYTES)
        val cursor = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(cursor.int == MAGIC)
        require(cursor.get().toInt() and 0xff == VERSION)
        val role = PendingPairingRole.fromWire(cursor.get().toInt() and 0xff)
        val replacing = when (cursor.get().toInt() and 0xff) {
            0 -> false
            1 -> true
            else -> throw IllegalArgumentException("Invalid pending pairing flags")
        }
        val requestedCapabilities = cursor.long
        require(requestedCapabilities in 0..PendingPairingPayload.MAX_CAPABILITIES)
        val fields = ArrayList<ByteArray>(FIELD_COUNT)
        try {
            repeat(FIELD_COUNT) {
                require(cursor.remaining() >= 4)
                val length = cursor.int
                require(length >= 0 && length <= cursor.remaining())
                ByteArray(length).also {
                    cursor.get(it)
                    fields += it
                }
            }
            require(!cursor.hasRemaining())
            val name = decodeUtf8(fields[1], PendingPairingPayload.MAX_NAME_BYTES)
            val safetyNumber = decodeAscii(fields[7], PendingPairingPayload.MAX_SAFETY_NUMBER_BYTES)
            val safetyCode = decodeAscii(fields[8], PendingPairingPayload.MAX_SAFETY_CODE_BYTES)
            return PendingPairingPayload(
                role = role,
                replacingExistingContact = replacing,
                requestedCapabilities = requestedCapabilities,
                contactId = fields[0],
                localContactName = name,
                offerQr = fields[2],
                responseQr = fields[3],
                sessionState = fields[4],
                remoteFingerprint = fields[5],
                routingTag = fields[6],
                safetyNumber = safetyNumber,
                safetyCode = safetyCode,
            )
        } finally {
            fields.forEach { it.fill(0) }
        }
    }

    private fun decodeUtf8(bytes: ByteArray, max: Int): String {
        require(bytes.size in 1..max)
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }

    private fun decodeAscii(bytes: ByteArray, max: Int): String {
        require(bytes.size <= max)
        require(bytes.all { it.toInt() and 0xff <= 0x7f })
        return String(bytes, StandardCharsets.US_ASCII)
    }

    const val MAX_ENCODED_BYTES = 512 * 1024
}
