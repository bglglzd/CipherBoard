package org.cipherboard.pairing

enum class PairingQrPayloadType {
    OFFER,
    RESPONSE,
}

enum class PairingQrValidationError {
    EMPTY,
    TOO_LARGE,
    NON_ASCII,
    UNSUPPORTED_PREFIX,
    EMPTY_BODY,
}

class PairingQrPayloadException(
    val reason: PairingQrValidationError,
) : IllegalArgumentException("Invalid pairing QR payload: ${reason.name}")

class PairingQrPayload private constructor(
    val value: String,
    val type: PairingQrPayloadType,
) {
    val sizeBytes: Int
        get() = value.length

    override fun equals(other: Any?): Boolean =
        other is PairingQrPayload && value == other.value && type == other.type

    override fun hashCode(): Int = 31 * value.hashCode() + type.hashCode()

    /** Avoid accidentally exposing the QR payload through generic debugging. */
    override fun toString(): String = "PairingQrPayload(type=$type,sizeBytes=$sizeBytes)"

    companion object {
        const val OFFER_PREFIX = "CBO1:"
        const val RESPONSE_PREFIX = "CBR1:"
        const val MAX_DECODED_BYTES = 32 * 1024

        @JvmStatic
        fun parse(raw: String): PairingQrPayload {
            if (raw.isEmpty()) throw PairingQrPayloadException(PairingQrValidationError.EMPTY)
            if (raw.length > MAX_DECODED_BYTES) {
                throw PairingQrPayloadException(PairingQrValidationError.TOO_LARGE)
            }
            if (raw.any { it.code !in PRINTABLE_ASCII }) {
                throw PairingQrPayloadException(PairingQrValidationError.NON_ASCII)
            }
            val type = when {
                raw.startsWith(OFFER_PREFIX) -> PairingQrPayloadType.OFFER
                raw.startsWith(RESPONSE_PREFIX) -> PairingQrPayloadType.RESPONSE
                else -> throw PairingQrPayloadException(PairingQrValidationError.UNSUPPORTED_PREFIX)
            }
            val prefixLength = if (type == PairingQrPayloadType.OFFER) OFFER_PREFIX.length else RESPONSE_PREFIX.length
            if (raw.length == prefixLength) {
                throw PairingQrPayloadException(PairingQrValidationError.EMPTY_BODY)
            }
            return PairingQrPayload(raw, type)
        }

        @JvmStatic
        fun parseOrNull(raw: String?): PairingQrPayload? {
            if (raw == null) return null
            return try {
                parse(raw)
            } catch (_: PairingQrPayloadException) {
                null
            }
        }

        private val PRINTABLE_ASCII = 0x21..0x7e
    }
}
