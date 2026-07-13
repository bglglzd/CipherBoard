package org.cipherboard.securestorage

import java.io.Closeable

enum class ContactVerificationStatus(val code: Int) {
    UNVERIFIED(1),
    VERIFIED(2),
    KEY_CHANGED(3),
    PAIRING_REQUIRED(4),
    SESSION_ERROR(5),
    ;

    companion object {
        internal fun fromCode(code: Int) = entries.firstOrNull { it.code == code }
            ?: throw DomainCodecException(DomainCodecError.INVALID_VALUE)
    }
}

enum class PendingPairingType(val code: Int) {
    OFFER(1),
    RESPONSE(2),
    ;

    companion object {
        internal fun fromCode(code: Int) = entries.firstOrNull { it.code == code }
            ?: throw DomainCodecException(DomainCodecError.INVALID_VALUE)
    }
}

enum class OneShotStatus(val code: Int) {
    ACTIVE(1),
    CONSUMED(2),
    CANCELLED(3),
    EXPIRED(4),
    ;

    companion object {
        internal fun fromCode(code: Int) = entries.firstOrNull { it.code == code }
            ?: throw DomainCodecException(DomainCodecError.INVALID_VALUE)
    }
}

class OwnerIdentityAccountState(
    val localOwnerName: String,
    accountState: ByteArray,
    identityFingerprint: ByteArray,
    val protocolVersion: Int,
    val createdAtEpochMillis: Long,
) : Closeable {
    init {
        validateLocalName(localOwnerName)
        require(accountState.size in 1..MAX_ACCOUNT_STATE_BYTES)
        require(identityFingerprint.size in MIN_FINGERPRINT_BYTES..MAX_FINGERPRINT_BYTES)
        require(protocolVersion in 1..MAX_PROTOCOL_VERSION)
        require(createdAtEpochMillis >= 0)
    }

    val accountState: ByteArray = accountState.copyOf()
    val identityFingerprint: ByteArray = identityFingerprint.copyOf()

    override fun close() {
        accountState.wipe()
        identityFingerprint.wipe()
    }

    override fun toString() = "OwnerIdentityAccountState(protocolVersion=$protocolVersion)"

    companion object {
        const val MAX_ACCOUNT_STATE_BYTES = 2 * 1024 * 1024
        const val MAX_LOCAL_NAME_UTF8_BYTES = 512
        const val MAX_LOCAL_NAME_CODE_POINTS = 128
        const val MIN_FINGERPRINT_BYTES = 16
        const val MAX_FINGERPRINT_BYTES = 128
        const val MAX_PROTOCOL_VERSION = 65_535

        internal fun validateLocalName(name: String) {
            require(name.isNotBlank())
            require(name.codePointCount(0, name.length) <= MAX_LOCAL_NAME_CODE_POINTS)
            val encoded = name.toByteArray(Charsets.UTF_8)
            try {
                require(encoded.size <= MAX_LOCAL_NAME_UTF8_BYTES)
            } finally {
                encoded.wipe()
            }
            require(name.none { it == '\u0000' || it == '\r' || it == '\n' || Character.isISOControl(it) })
        }
    }
}

class ContactVaultEntry(
    internalId: ByteArray,
    val localName: String,
    remoteIdentityFingerprint: ByteArray,
    remoteSessionTag: ByteArray,
    val verificationStatus: ContactVerificationStatus,
    val pairedAtEpochMillis: Long,
    val lastActiveAtEpochMillis: Long,
    val protocolVersion: Int,
    val safetyNumber: String,
    val safetyCode: String,
    val requiresRepairing: Boolean,
    val sessionError: Boolean,
    val keyChanged: Boolean,
) : Closeable {
    init {
        require(internalId.size in MIN_ID_BYTES..MAX_ID_BYTES)
        validateLocalName(localName)
        require(remoteIdentityFingerprint.size in OwnerIdentityAccountState.MIN_FINGERPRINT_BYTES..
            OwnerIdentityAccountState.MAX_FINGERPRINT_BYTES)
        require(remoteSessionTag.size in MIN_TAG_BYTES..MAX_TAG_BYTES)
        require(pairedAtEpochMillis >= 0 && lastActiveAtEpochMillis >= pairedAtEpochMillis)
        require(protocolVersion in 1..OwnerIdentityAccountState.MAX_PROTOCOL_VERSION)
        validateSafetyNumber(safetyNumber)
        validateSafetyCode(safetyCode)
        require(keyChanged == (verificationStatus == ContactVerificationStatus.KEY_CHANGED))
        require(sessionError == (verificationStatus == ContactVerificationStatus.SESSION_ERROR))
        require(
            requiresRepairing == (verificationStatus == ContactVerificationStatus.KEY_CHANGED ||
                verificationStatus == ContactVerificationStatus.PAIRING_REQUIRED ||
                verificationStatus == ContactVerificationStatus.SESSION_ERROR),
        )
    }

    val internalId = internalId.copyOf()
    val remoteIdentityFingerprint = remoteIdentityFingerprint.copyOf()
    val remoteSessionTag = remoteSessionTag.copyOf()

    override fun close() {
        internalId.wipe()
        remoteIdentityFingerprint.wipe()
        remoteSessionTag.wipe()
    }

    override fun toString() = "ContactVaultEntry(status=$verificationStatus,protocolVersion=$protocolVersion)"

    internal fun copyWith(
        localName: String = this.localName,
        verificationStatus: ContactVerificationStatus = this.verificationStatus,
        safetyNumber: String = this.safetyNumber,
        safetyCode: String = this.safetyCode,
        requiresRepairing: Boolean = this.requiresRepairing,
        sessionError: Boolean = this.sessionError,
        keyChanged: Boolean = this.keyChanged,
        lastActiveAtEpochMillis: Long = this.lastActiveAtEpochMillis,
    ) = ContactVaultEntry(
        internalId,
        localName,
        remoteIdentityFingerprint,
        remoteSessionTag,
        verificationStatus,
        pairedAtEpochMillis,
        lastActiveAtEpochMillis,
        protocolVersion,
        safetyNumber,
        safetyCode,
        requiresRepairing,
        sessionError,
        keyChanged,
    )

    companion object {
        const val MIN_ID_BYTES = 16
        const val MAX_ID_BYTES = 64
        const val MIN_TAG_BYTES = 8
        const val MAX_TAG_BYTES = 64
        const val MAX_LOCAL_NAME_UTF8_BYTES = 512
        const val MAX_LOCAL_NAME_CODE_POINTS = 128
        const val MAX_SAFETY_NUMBER_ASCII_BYTES = 96
        const val MAX_SAFETY_CODE_ASCII_BYTES = 128

        internal fun validateLocalName(name: String) {
            OwnerIdentityAccountState.validateLocalName(name)
        }

        private fun validateSafetyNumber(value: String) {
            require(value.length in 1..MAX_SAFETY_NUMBER_ASCII_BYTES)
            require(value.first().isDigit() && value.last().isDigit())
            require(value.all { it in '0'..'9' || it == ' ' })
            require("  " !in value)
        }

        private fun validateSafetyCode(value: String) {
            require(value.length in 1..MAX_SAFETY_CODE_ASCII_BYTES)
            require(value.first() != ' ' && value.last() != ' ')
            require(value.all { it.code in 0x21..0x7e || it == ' ' })
            require("  " !in value)
        }
    }
}

class PendingPairingState(
    val type: PendingPairingType,
    pairingId: ByteArray,
    val createdAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    nonce: ByteArray,
    transcriptHash: ByteArray,
    val oneShotStatus: OneShotStatus,
    val protocolVersion: Int,
    payload: ByteArray,
) : Closeable {
    init {
        require(pairingId.size in ContactVaultEntry.MIN_ID_BYTES..ContactVaultEntry.MAX_ID_BYTES)
        require(createdAtEpochMillis >= 0 && expiresAtEpochMillis >= createdAtEpochMillis)
        require(nonce.size in MIN_NONCE_BYTES..MAX_NONCE_BYTES)
        require(transcriptHash.size in MIN_HASH_BYTES..MAX_HASH_BYTES)
        require(protocolVersion in 1..OwnerIdentityAccountState.MAX_PROTOCOL_VERSION)
        require(payload.size in 1..MAX_PAYLOAD_BYTES)
    }

    val pairingId = pairingId.copyOf()
    val nonce = nonce.copyOf()
    val transcriptHash = transcriptHash.copyOf()
    val payload = payload.copyOf()

    override fun close() {
        pairingId.wipe()
        nonce.wipe()
        transcriptHash.wipe()
        payload.wipe()
    }

    override fun toString() = "PendingPairingState(type=$type,status=$oneShotStatus)"

    internal fun copyWithStatus(status: OneShotStatus) = PendingPairingState(
        type,
        pairingId,
        createdAtEpochMillis,
        expiresAtEpochMillis,
        nonce,
        transcriptHash,
        status,
        protocolVersion,
        // Keep a one-shot tombstone, never a duplicate initial session, after terminal transition.
        if (status == OneShotStatus.ACTIVE) payload else TERMINAL_TOMBSTONE,
    )

    companion object {
        const val MIN_NONCE_BYTES = 16
        const val MAX_NONCE_BYTES = 64
        const val MIN_HASH_BYTES = 32
        const val MAX_HASH_BYTES = 64
        const val MAX_PAYLOAD_BYTES = 512 * 1024
        private val TERMINAL_TOMBSTONE = byteArrayOf(0)
    }
}

data class VersionedDomainRecord<T : Closeable>(
    val revision: Long,
    val value: T,
) : Closeable {
    override fun close() = value.close()
}
