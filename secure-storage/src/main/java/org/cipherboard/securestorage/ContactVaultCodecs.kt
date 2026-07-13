package org.cipherboard.securestorage

internal object OwnerAccountCodec {
    private const val MAGIC = 0x43424f41 // CBOA
    private const val VERSION = 1
    private const val MAX_RECORD_BYTES = 3 * 1024 * 1024

    private val localOwnerName = BinaryFieldSpec(
        1,
        BinaryFieldType.UTF8,
        maxBytes = OwnerIdentityAccountState.MAX_LOCAL_NAME_UTF8_BYTES,
    )
    private val accountState = BinaryFieldSpec(
        2,
        BinaryFieldType.BYTES,
        maxBytes = OwnerIdentityAccountState.MAX_ACCOUNT_STATE_BYTES,
    )
    private val identityFingerprint = BinaryFieldSpec(
        3,
        BinaryFieldType.BYTES,
        maxBytes = OwnerIdentityAccountState.MAX_FINGERPRINT_BYTES,
    )
    private val protocolVersion = BinaryFieldSpec(4, BinaryFieldType.U32, maxBytes = Int.SIZE_BYTES)
    private val createdAt = BinaryFieldSpec(5, BinaryFieldType.U64, maxBytes = Long.SIZE_BYTES)
    private val specs = listOf(localOwnerName, accountState, identityFingerprint, protocolVersion, createdAt)

    fun encode(value: OwnerIdentityAccountState): ByteArray {
        val fields = listOf(
            StrictBinaryCodec.utf8(localOwnerName, value.localOwnerName),
            StrictBinaryCodec.bytes(accountState, value.accountState),
            StrictBinaryCodec.bytes(identityFingerprint, value.identityFingerprint),
            StrictBinaryCodec.u32(protocolVersion, value.protocolVersion),
            StrictBinaryCodec.u64(createdAt, value.createdAtEpochMillis),
        )
        return try {
            StrictBinaryCodec.encode(MAGIC, VERSION, MAX_RECORD_BYTES, fields)
        } finally {
            StrictBinaryCodec.wipeFields(fields)
        }
    }

    fun decode(encoded: ByteArray): OwnerIdentityAccountState =
        StrictBinaryCodec.decode(encoded, MAGIC, VERSION, MAX_RECORD_BYTES, specs).use { fields ->
            val account = fields.takeBytes(accountState.id)
            val fingerprint = fields.takeBytes(identityFingerprint.id)
            try {
                constructDomainValue {
                    OwnerIdentityAccountState(
                        fields.utf8(localOwnerName.id),
                        account,
                        fingerprint,
                        fields.u32(protocolVersion.id),
                        fields.u64(createdAt.id),
                    )
                }
            } finally {
                account.wipe()
                fingerprint.wipe()
            }
        }
}

internal object ContactEntryCodec {
    private const val MAGIC = 0x43424354 // CBCT
    private const val VERSION = 1
    private const val MAX_RECORD_BYTES = 3 * 1024 * 1024

    private val internalId = BinaryFieldSpec(
        1,
        BinaryFieldType.BYTES,
        maxBytes = ContactVaultEntry.MAX_ID_BYTES,
    )
    private val localName = BinaryFieldSpec(
        2,
        BinaryFieldType.UTF8,
        maxBytes = ContactVaultEntry.MAX_LOCAL_NAME_UTF8_BYTES,
    )
    private val identityFingerprint = BinaryFieldSpec(
        3,
        BinaryFieldType.BYTES,
        maxBytes = OwnerIdentityAccountState.MAX_FINGERPRINT_BYTES,
    )
    private val sessionTag = BinaryFieldSpec(
        4,
        BinaryFieldType.BYTES,
        maxBytes = ContactVaultEntry.MAX_TAG_BYTES,
    )
    private val verificationStatus = BinaryFieldSpec(5, BinaryFieldType.ENUM, maxBytes = Int.SIZE_BYTES)
    private val pairedAt = BinaryFieldSpec(6, BinaryFieldType.U64, maxBytes = Long.SIZE_BYTES)
    private val lastActiveAt = BinaryFieldSpec(7, BinaryFieldType.U64, maxBytes = Long.SIZE_BYTES)
    private val protocolVersion = BinaryFieldSpec(8, BinaryFieldType.U32, maxBytes = Int.SIZE_BYTES)
    private val sessionState = BinaryFieldSpec(
        9,
        BinaryFieldType.BYTES,
        maxBytes = ContactVaultEntry.MAX_SESSION_BYTES,
    )
    private val replayState = BinaryFieldSpec(
        10,
        BinaryFieldType.BYTES,
        maxBytes = ContactVaultEntry.MAX_REPLAY_STATE_BYTES,
    )
    private val requiresRepairing = BinaryFieldSpec(11, BinaryFieldType.BOOLEAN, maxBytes = 1)
    private val sessionError = BinaryFieldSpec(12, BinaryFieldType.BOOLEAN, maxBytes = 1)
    private val keyChanged = BinaryFieldSpec(13, BinaryFieldType.BOOLEAN, maxBytes = 1)
    private val specs = listOf(
        internalId,
        localName,
        identityFingerprint,
        sessionTag,
        verificationStatus,
        pairedAt,
        lastActiveAt,
        protocolVersion,
        sessionState,
        replayState,
        requiresRepairing,
        sessionError,
        keyChanged,
    )

    fun encode(value: ContactVaultEntry): ByteArray {
        val fields = listOf(
            StrictBinaryCodec.bytes(internalId, value.internalId),
            StrictBinaryCodec.utf8(localName, value.localName),
            StrictBinaryCodec.bytes(identityFingerprint, value.remoteIdentityFingerprint),
            StrictBinaryCodec.bytes(sessionTag, value.remoteSessionTag),
            StrictBinaryCodec.enum(verificationStatus, value.verificationStatus.code),
            StrictBinaryCodec.u64(pairedAt, value.pairedAtEpochMillis),
            StrictBinaryCodec.u64(lastActiveAt, value.lastActiveAtEpochMillis),
            StrictBinaryCodec.u32(protocolVersion, value.protocolVersion),
            StrictBinaryCodec.bytes(sessionState, value.olmSessionState),
            StrictBinaryCodec.bytes(replayState, value.replayState),
            StrictBinaryCodec.bool(requiresRepairing, value.requiresRepairing),
            StrictBinaryCodec.bool(sessionError, value.sessionError),
            StrictBinaryCodec.bool(keyChanged, value.keyChanged),
        )
        return try {
            StrictBinaryCodec.encode(MAGIC, VERSION, MAX_RECORD_BYTES, fields)
        } finally {
            StrictBinaryCodec.wipeFields(fields)
        }
    }

    fun decode(encoded: ByteArray): ContactVaultEntry =
        StrictBinaryCodec.decode(encoded, MAGIC, VERSION, MAX_RECORD_BYTES, specs).use { fields ->
            val id = fields.takeBytes(internalId.id)
            val fingerprint = fields.takeBytes(identityFingerprint.id)
            val tag = fields.takeBytes(sessionTag.id)
            val session = fields.takeBytes(sessionState.id)
            val replay = fields.takeBytes(replayState.id)
            try {
                constructDomainValue {
                    ContactVaultEntry(
                        id,
                        fields.utf8(localName.id),
                        fingerprint,
                        tag,
                        ContactVerificationStatus.fromCode(fields.enum(verificationStatus.id)),
                        fields.u64(pairedAt.id),
                        fields.u64(lastActiveAt.id),
                        fields.u32(protocolVersion.id),
                        session,
                        replay,
                        fields.bool(requiresRepairing.id),
                        fields.bool(sessionError.id),
                        fields.bool(keyChanged.id),
                    )
                }
            } finally {
                id.wipe()
                fingerprint.wipe()
                tag.wipe()
                session.wipe()
                replay.wipe()
            }
        }
}

internal object PendingPairingCodec {
    private const val MAGIC = 0x43425052 // CBPR
    private const val VERSION = 1
    private const val MAX_RECORD_BYTES = 1024 * 1024

    private val type = BinaryFieldSpec(1, BinaryFieldType.ENUM, maxBytes = Int.SIZE_BYTES)
    private val pairingId = BinaryFieldSpec(
        2,
        BinaryFieldType.BYTES,
        maxBytes = ContactVaultEntry.MAX_ID_BYTES,
    )
    private val createdAt = BinaryFieldSpec(3, BinaryFieldType.U64, maxBytes = Long.SIZE_BYTES)
    private val expiresAt = BinaryFieldSpec(4, BinaryFieldType.U64, maxBytes = Long.SIZE_BYTES)
    private val nonce = BinaryFieldSpec(
        5,
        BinaryFieldType.BYTES,
        maxBytes = PendingPairingState.MAX_NONCE_BYTES,
    )
    private val transcriptHash = BinaryFieldSpec(
        6,
        BinaryFieldType.BYTES,
        maxBytes = PendingPairingState.MAX_HASH_BYTES,
    )
    private val oneShotStatus = BinaryFieldSpec(7, BinaryFieldType.ENUM, maxBytes = Int.SIZE_BYTES)
    private val protocolVersion = BinaryFieldSpec(8, BinaryFieldType.U32, maxBytes = Int.SIZE_BYTES)
    private val payload = BinaryFieldSpec(
        9,
        BinaryFieldType.BYTES,
        maxBytes = PendingPairingState.MAX_PAYLOAD_BYTES,
    )
    private val specs = listOf(
        type,
        pairingId,
        createdAt,
        expiresAt,
        nonce,
        transcriptHash,
        oneShotStatus,
        protocolVersion,
        payload,
    )

    fun encode(value: PendingPairingState): ByteArray {
        val fields = listOf(
            StrictBinaryCodec.enum(type, value.type.code),
            StrictBinaryCodec.bytes(pairingId, value.pairingId),
            StrictBinaryCodec.u64(createdAt, value.createdAtEpochMillis),
            StrictBinaryCodec.u64(expiresAt, value.expiresAtEpochMillis),
            StrictBinaryCodec.bytes(nonce, value.nonce),
            StrictBinaryCodec.bytes(transcriptHash, value.transcriptHash),
            StrictBinaryCodec.enum(oneShotStatus, value.oneShotStatus.code),
            StrictBinaryCodec.u32(protocolVersion, value.protocolVersion),
            StrictBinaryCodec.bytes(payload, value.payload),
        )
        return try {
            StrictBinaryCodec.encode(MAGIC, VERSION, MAX_RECORD_BYTES, fields)
        } finally {
            StrictBinaryCodec.wipeFields(fields)
        }
    }

    fun decode(encoded: ByteArray): PendingPairingState =
        StrictBinaryCodec.decode(encoded, MAGIC, VERSION, MAX_RECORD_BYTES, specs).use { fields ->
            val id = fields.takeBytes(pairingId.id)
            val nonceBytes = fields.takeBytes(nonce.id)
            val transcript = fields.takeBytes(transcriptHash.id)
            val pairingPayload = fields.takeBytes(payload.id)
            try {
                constructDomainValue {
                    PendingPairingState(
                        PendingPairingType.fromCode(fields.enum(type.id)),
                        id,
                        fields.u64(createdAt.id),
                        fields.u64(expiresAt.id),
                        nonceBytes,
                        transcript,
                        OneShotStatus.fromCode(fields.enum(oneShotStatus.id)),
                        fields.u32(protocolVersion.id),
                        pairingPayload,
                    )
                }
            } finally {
                id.wipe()
                nonceBytes.wipe()
                transcript.wipe()
                pairingPayload.wipe()
            }
        }
}

private inline fun <T> constructDomainValue(block: () -> T): T = try {
    block()
} catch (error: DomainCodecException) {
    throw error
} catch (_: IllegalArgumentException) {
    throw DomainCodecException(DomainCodecError.INVALID_VALUE)
}
