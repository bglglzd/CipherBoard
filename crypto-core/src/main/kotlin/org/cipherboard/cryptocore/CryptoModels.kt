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
)

class PairingCompleted(
    val accountState: OwnedSecret,
    val sessionState: OwnedSecret,
    val safetyCode: SafetyCode,
    val remoteIdentity: PublicIdentity,
)

enum class TransportMode(internal val wireValue: Int) {
    UNIVERSAL(0),
    SMS_COMPACT(1),
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

class CryptoCoreException(val errorCode: Int) :
    IllegalStateException("CipherBoard crypto error $errorCode")
