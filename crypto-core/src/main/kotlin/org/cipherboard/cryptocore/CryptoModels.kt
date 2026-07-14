package org.cipherboard.cryptocore

class PublicIdentity(
    val curve25519: ByteArray,
    val ed25519: ByteArray,
) {
    init {
        require(curve25519.size == 32)
        require(ed25519.size == 32)
    }

    override fun toString(): String = "PublicIdentity(redacted)"
}

class SafetyCode(
    val hash: ByteArray,
    val decimalGroups: String,
    val wordCode: String,
) {
    init {
        require(hash.size == 32)
    }

    override fun toString(): String = "SafetyCode(redacted)"
}

data class ProtocolVersions(val cipherBoard: Int, val olmSession: Int)

class AccountCreated(
    val accountState: OwnedSecret,
    val identity: PublicIdentity,
    val fingerprint: ByteArray,
)

class OfferCreated(
    val accountState: OwnedSecret,
    val offerQr: ByteArray,
)

class PairingResponseCreated(
    val sessionState: OwnedSecret,
    val responseQr: ByteArray,
    val safetyCode: SafetyCode,
    val remoteIdentity: PublicIdentity,
    val routingTag: ByteArray,
    val remoteIdentityFingerprint: ByteArray,
) {
    init {
        require(routingTag.size == 16)
        require(remoteIdentityFingerprint.size == 32)
    }
}

class PairingCompleted(
    val accountState: OwnedSecret,
    val sessionState: OwnedSecret,
    val safetyCode: SafetyCode,
    val remoteIdentity: PublicIdentity,
    val routingTag: ByteArray,
    val remoteIdentityFingerprint: ByteArray,
) {
    init {
        require(routingTag.size == 16)
        require(remoteIdentityFingerprint.size == 32)
    }
}

enum class PairingPayloadType(internal val wireValue: Int) {
    OFFER(1),
    RESPONSE(2),
    ;

    companion object {
        internal fun fromWire(value: Int): PairingPayloadType = entries.firstOrNull { it.wireValue == value }
            ?: throw IllegalArgumentException("Unknown pairing payload type")
    }
}

enum class PairingPayloadStatus {
    VALID,
    EXPIRED,
}

class PairingPayloadMetadata(
    val type: PairingPayloadType,
    val pairingId: ByteArray,
    val remoteIdentity: PublicIdentity,
    val remoteIdentityFingerprint: ByteArray,
    val nonce: ByteArray,
    val capabilities: Long,
    val expiresAtEpochSeconds: Long?,
    val status: PairingPayloadStatus,
    val offerHash: ByteArray,
) {
    init {
        require(pairingId.size == 16)
        require(remoteIdentityFingerprint.size == 32)
        require(nonce.size == 32)
        require(capabilities in 0..0xffff_ffffL)
        require(expiresAtEpochSeconds == null || expiresAtEpochSeconds > 0)
        require(offerHash.size == 32)
        require(type == PairingPayloadType.OFFER || expiresAtEpochSeconds == null)
        require(type == PairingPayloadType.OFFER || status == PairingPayloadStatus.VALID)
    }

    override fun toString(): String = "PairingPayloadMetadata(type=$type,status=$status)"
}

enum class TransportMode(internal val wireValue: Int) {
    UNIVERSAL(0),
    SMS_COMPACT(1),
}

enum class TransportPresentation(internal val wireValue: Int) {
    COMPACT(0),
    RUSSIAN_WORDS(1),
    ENGLISH_WORDS(2),
    ;

    companion object {
        internal fun fromWire(value: Int): TransportPresentation =
            entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unknown transport presentation")
    }
}

class PresentationDecoded(
    val presentation: TransportPresentation,
    parts: List<String>,
) {
    val parts: List<String> = parts.toList()

    init {
        require(parts.isNotEmpty())
    }

    override fun toString(): String =
        "PresentationDecoded(presentation=$presentation,parts=${parts.size})"
}

class EncryptionPrepared(
    val sessionState: OwnedSecret,
    val messageId: ByteArray,
    val parts: List<String>,
)

class DecryptionPrepared(
    val sessionState: OwnedSecret,
    val messageId: ByteArray,
    val plaintext: OwnedSecret,
)

data class EnvelopeMetadata(
    val routingTag: ByteArray,
    val messageId: ByteArray,
    val partNumber: Int,
    val totalParts: Int,
    val capabilities: Long,
    val olmType: Int,
    val payloadBytes: Long,
)

enum class CryptoErrorCode(val wireValue: Int) {
    INVALID_INPUT(1),
    SIZE_LIMIT(2),
    UNSUPPORTED_VERSION(3),
    INVALID_ENCODING(4),
    MISSING_FIELD(5),
    DUPLICATE_FIELD(6),
    UNKNOWN_MANDATORY_FIELD(7),
    INVALID_SIGNATURE(8),
    EXPIRED_OFFER(9),
    INVALID_TRANSCRIPT(10),
    PAIRING_ALREADY_USED(11),
    CRYPTO_FAILURE(12),
    WRONG_CONTACT(13),
    REPLAY(14),
    MISSING_PART(15),
    INCONSISTENT_PARTS(16),
    TOO_MANY_PARTS(17),
    INVALID_UTF8(18),
    INVALID_STATE(19),
    RANDOM_FAILURE(20),
    UNKNOWN(-1),
    ;

    companion object {
        internal fun fromWire(value: Int): CryptoErrorCode = entries.firstOrNull { it.wireValue == value } ?: UNKNOWN
    }
}

class CryptoCoreException(val errorCode: Int) :
    IllegalStateException("CipherBoard crypto error $errorCode") {
    val reason: CryptoErrorCode = CryptoErrorCode.fromWire(errorCode)
}
