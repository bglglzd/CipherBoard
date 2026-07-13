package org.cipherboard.securestorage

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ContactVaultCodecsTest {
    @Test
    fun ownerAccountEncodingIsDeterministicAndRoundTrips() {
        owner().use { source ->
            val first = OwnerAccountCodec.encode(source)
            val second = OwnerAccountCodec.encode(source)
            try {
                assertArrayEquals(first, second)
                OwnerAccountCodec.decode(first).use { decoded ->
                    assertEquals(source.localOwnerName, decoded.localOwnerName)
                    assertArrayEquals(source.accountState, decoded.accountState)
                    assertArrayEquals(source.identityFingerprint, decoded.identityFingerprint)
                    assertEquals(source.protocolVersion, decoded.protocolVersion)
                    assertEquals(source.createdAtEpochMillis, decoded.createdAtEpochMillis)
                }
            } finally {
                first.wipe()
                second.wipe()
            }
        }
    }

    @Test
    fun contactMetadataAndPendingPairingRoundTripUnicodeAndBinaryState() {
        contact().use { source ->
            val encoded = ContactEntryCodec.encode(source)
            try {
                ContactEntryCodec.decode(encoded).use { decoded ->
                    assertEquals(source.localName, decoded.localName)
                    assertArrayEquals(source.internalId, decoded.internalId)
                    assertArrayEquals(source.remoteIdentityFingerprint, decoded.remoteIdentityFingerprint)
                    assertArrayEquals(source.remoteSessionTag, decoded.remoteSessionTag)
                    assertEquals(source.verificationStatus, decoded.verificationStatus)
                    assertEquals(source.safetyNumber, decoded.safetyNumber)
                    assertEquals(source.safetyCode, decoded.safetyCode)
                    assertEquals(source.requiresRepairing, decoded.requiresRepairing)
                    assertEquals(source.sessionError, decoded.sessionError)
                    assertEquals(source.keyChanged, decoded.keyChanged)
                }
            } finally {
                encoded.wipe()
            }
        }
        pending().use { source ->
            val encoded = PendingPairingCodec.encode(source)
            try {
                PendingPairingCodec.decode(encoded).use { decoded ->
                    assertEquals(source.type, decoded.type)
                    assertArrayEquals(source.pairingId, decoded.pairingId)
                    assertArrayEquals(source.nonce, decoded.nonce)
                    assertArrayEquals(source.transcriptHash, decoded.transcriptHash)
                    assertEquals(source.oneShotStatus, decoded.oneShotStatus)
                    assertArrayEquals(source.payload, decoded.payload)
                }
            } finally {
                encoded.wipe()
            }
        }
    }

    @Test
    fun parserRejectsDuplicateAndUnknownRequiredFieldsButSkipsUnknownOptionalFields() {
        owner().use { value ->
            val valid = OwnerAccountCodec.encode(value)
            val optional = appendField(valid, 100, required = false, byteArrayOf(7, 8))
            val required = appendField(valid, 100, required = true, byteArrayOf(7, 8))
            val duplicate = appendField(valid, 5, required = true, ByteArray(Long.SIZE_BYTES))
            try {
                OwnerAccountCodec.decode(optional).close()
                assertCodecError(DomainCodecError.UNKNOWN_REQUIRED_FIELD) {
                    OwnerAccountCodec.decode(required).close()
                }
                assertCodecError(DomainCodecError.DUPLICATE_FIELD) {
                    OwnerAccountCodec.decode(duplicate).close()
                }
            } finally {
                valid.wipe()
                optional.wipe()
                required.wipe()
                duplicate.wipe()
            }
        }
    }

    @Test
    fun parserRejectsWrongVersionTrailingDataAndOversizedLength() {
        owner().use { value ->
            val valid = OwnerAccountCodec.encode(value)
            val wrongVersion = valid.copyOf().apply {
                this[4] = 0
                this[5] = 2
            }
            val trailing = valid + byteArrayOf(1)
            val oversizedLength = valid.copyOf().apply {
                ByteBuffer.wrap(this).order(ByteOrder.BIG_ENDIAN).putInt(12, Int.MAX_VALUE)
            }
            try {
                assertCodecError(DomainCodecError.UNSUPPORTED_VERSION) {
                    OwnerAccountCodec.decode(wrongVersion).close()
                }
                assertCodecError(DomainCodecError.TRAILING_DATA) {
                    OwnerAccountCodec.decode(trailing).close()
                }
                assertCodecError(DomainCodecError.TRUNCATED) {
                    OwnerAccountCodec.decode(oversizedLength).close()
                }
            } finally {
                valid.wipe()
                wrongVersion.wipe()
                trailing.wipe()
                oversizedLength.wipe()
            }
        }
    }

    @Test
    fun contactCodecRejectsPreMetadataOnlyVersion() {
        contact().use { value ->
            val encoded = ContactEntryCodec.encode(value)
            val oldVersion = encoded.copyOf().apply {
                this[4] = 0
                this[5] = 1
            }
            try {
                assertCodecError(DomainCodecError.UNSUPPORTED_VERSION) {
                    ContactEntryCodec.decode(oldVersion).close()
                }
            } finally {
                encoded.wipe()
                oldVersion.wipe()
            }
        }
    }

    @Test
    fun arbitraryBoundedInputsNeverEscapeAsUnexpectedParserExceptions() {
        val random = Random(0x43425052L)
        repeat(2_000) {
            val bytes = ByteArray(random.nextInt(4_096)).also(random::nextBytes)
            assertOnlyCodecFailure(bytes, OwnerAccountCodec::decode)
            assertOnlyCodecFailure(bytes, ContactEntryCodec::decode)
            assertOnlyCodecFailure(bytes, PendingPairingCodec::decode)
            bytes.wipe()
        }
    }

    @Test
    fun domainModelsRejectUnsafeNamesAndContradictoryContactStatus() {
        assertThrows(IllegalArgumentException::class.java) {
            OwnerIdentityAccountState(
                localOwnerName = "owner\nname",
                accountState = ByteArray(1),
                identityFingerprint = ByteArray(32),
                protocolVersion = 1,
                createdAtEpochMillis = 0,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            ContactVaultEntry(
                internalId = ByteArray(16),
                localName = "Bob",
                remoteIdentityFingerprint = ByteArray(32),
                remoteSessionTag = ByteArray(16),
                verificationStatus = ContactVerificationStatus.VERIFIED,
                pairedAtEpochMillis = 0,
                lastActiveAtEpochMillis = 0,
                protocolVersion = 1,
                safetyNumber = "1234 5678",
                safetyCode = "amber beacon",
                requiresRepairing = true,
                sessionError = false,
                keyChanged = false,
            )
        }
    }

    private fun <T : AutoCloseable> assertOnlyCodecFailure(bytes: ByteArray, decode: (ByteArray) -> T) {
        try {
            decode(bytes).close()
        } catch (_: DomainCodecException) {
            // Expected for malformed input.
        }
    }

    private fun assertCodecError(reason: DomainCodecError, block: () -> Unit) {
        val error = assertThrows(DomainCodecException::class.java, block)
        assertEquals(reason, error.reason)
    }

    private fun appendField(
        encoded: ByteArray,
        id: Int,
        required: Boolean,
        value: ByteArray,
    ): ByteArray {
        val result = ByteBuffer.allocate(encoded.size + 8 + value.size).order(ByteOrder.BIG_ENDIAN)
        result.put(encoded)
        val originalCount = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN).getShort(6).toInt() and 0xffff
        result.putShort(6, (originalCount + 1).toShort())
        result.position(encoded.size)
        result.putShort(id.toShort())
        result.put(if (required) 1 else 0)
        result.put(BinaryFieldType.BYTES.code.toByte())
        result.putInt(value.size)
        result.put(value)
        return result.array()
    }

    private fun owner() = OwnerIdentityAccountState(
        localOwnerName = "Владелец e\u0301",
        accountState = ByteArray(257) { (it * 7).toByte() },
        identityFingerprint = ByteArray(32) { (it + 11).toByte() },
        protocolVersion = 1,
        createdAtEpochMillis = 1_700_000_000_000,
    )

    private fun contact() = ContactVaultEntry(
        internalId = ByteArray(16) { (it + 1).toByte() },
        localName = "Алиса 🔐 e\u0301",
        remoteIdentityFingerprint = ByteArray(32) { (it + 2).toByte() },
        remoteSessionTag = ByteArray(16) { (it + 3).toByte() },
        verificationStatus = ContactVerificationStatus.VERIFIED,
        pairedAtEpochMillis = 1_700_000_000_000,
        lastActiveAtEpochMillis = 1_700_000_000_100,
        protocolVersion = 1,
        safetyNumber = "12345 67890 12345 67890",
        safetyCode = "amber beacon cedar delta",
        requiresRepairing = false,
        sessionError = false,
        keyChanged = false,
    )

    private fun pending() = PendingPairingState(
        type = PendingPairingType.OFFER,
        pairingId = ByteArray(16) { (it + 4).toByte() },
        createdAtEpochMillis = 1_700_000_000_000,
        expiresAtEpochMillis = 1_700_000_300_000,
        nonce = ByteArray(32) { (it + 5).toByte() },
        transcriptHash = ByteArray(32) { (it + 6).toByte() },
        oneShotStatus = OneShotStatus.ACTIVE,
        protocolVersion = 1,
        payload = ByteArray(511) { (it * 11).toByte() },
    )
}
