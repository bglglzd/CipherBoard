package org.cipherboard.cryptocore

class CipherBoardCrypto {
    fun protocolVersions(): ProtocolVersions = invoke(OP_PROTOCOL, request(1)) { payload ->
        payload.array(2)
        val result = ProtocolVersions(payload.uint().toInt(), payload.uint().toInt())
        payload.finish()
        result
    }

    fun createAccount(): AccountCreated = invoke(OP_CREATE_ACCOUNT, request(1)) { payload ->
        payload.array(4)
        val state = payload.bytes(MAX_ACCOUNT_STATE)
        try {
            val identity = payload.identity()
            val fingerprint = payload.bytes(32)
            payload.finish()
            AccountCreated(OwnedSecret.takeOwnership(state), identity, fingerprint)
        } catch (error: Throwable) {
            state.fill(0)
            throw error
        }
    }

    fun createOffer(
        accountState: OwnedSecret,
        nowEpochSeconds: Long,
        ttlSeconds: Long,
        capabilities: Long,
    ): OfferCreated {
        val request = CborWriter().use { writer ->
            writer.array(5).uint(WIRE_VERSION.toLong())
            accountState.use(writer::bytes)
            writer.uint(nowEpochSeconds).uint(ttlSeconds).uint(capabilities)
            writer.finish()
        }
        return invoke(OP_CREATE_OFFER, request) { payload ->
            payload.array(2)
            val state = payload.bytes(MAX_ACCOUNT_STATE)
            try {
                val qr = payload.bytes(MAX_PAIRING)
                payload.finish()
                OfferCreated(OwnedSecret.takeOwnership(state), qr)
            } catch (error: Throwable) {
                state.fill(0)
                throw error
            }
        }
    }

    fun respondToOffer(
        accountState: OwnedSecret,
        offerQr: ByteArray,
        nowEpochSeconds: Long,
        capabilities: Long,
    ): PairingResponseCreated {
        val request = CborWriter().use { writer ->
            writer.array(5).uint(WIRE_VERSION.toLong())
            accountState.use(writer::bytes)
            writer.bytes(offerQr).uint(nowEpochSeconds).uint(capabilities)
            writer.finish()
        }
        return invoke(OP_RESPOND_OFFER, request) { payload ->
            payload.array(9)
            val session = payload.bytes(MAX_SESSION_STATE)
            try {
                val responseQr = payload.bytes(MAX_PAIRING)
                val safety = payload.safetyCode()
                val remote = payload.identity()
                val routingTag = payload.bytes(16)
                val remoteFingerprint = payload.bytes(32)
                payload.finish()
                PairingResponseCreated(
                    OwnedSecret.takeOwnership(session),
                    responseQr,
                    safety,
                    remote,
                    routingTag,
                    remoteFingerprint,
                )
            } catch (error: Throwable) {
                session.fill(0)
                throw error
            }
        }
    }

    fun completePairing(
        accountState: OwnedSecret,
        offerQr: ByteArray,
        responseQr: ByteArray,
        nowEpochSeconds: Long,
    ): PairingCompleted {
        val request = CborWriter().use { writer ->
            writer.array(5).uint(WIRE_VERSION.toLong())
            accountState.use(writer::bytes)
            writer.bytes(offerQr).bytes(responseQr).uint(nowEpochSeconds)
            writer.finish()
        }
        return invoke(OP_COMPLETE_PAIRING, request) { payload ->
            payload.array(10)
            val updatedAccount = payload.bytes(MAX_ACCOUNT_STATE)
            val session = payload.bytes(MAX_SESSION_STATE)
            try {
                require(payload.bytes(0).isEmpty())
                val safety = payload.safetyCode()
                val remote = payload.identity()
                val routingTag = payload.bytes(16)
                val remoteFingerprint = payload.bytes(32)
                payload.finish()
                PairingCompleted(
                    OwnedSecret.takeOwnership(updatedAccount),
                    OwnedSecret.takeOwnership(session),
                    safety,
                    remote,
                    routingTag,
                    remoteFingerprint,
                )
            } catch (error: Throwable) {
                updatedAccount.fill(0)
                session.fill(0)
                throw error
            }
        }
    }

    fun encrypt(
        sessionState: OwnedSecret,
        plaintext: OwnedSecret,
        capabilities: Long,
        mode: TransportMode,
    ): EncryptionPrepared {
        require(plaintext.size <= MAX_PLAINTEXT_BYTES) { "Plaintext exceeds protocol limit" }
        val request = CborWriter(initialCapacity = plaintext.size + 256).use { writer ->
            writer.array(5).uint(WIRE_VERSION.toLong())
            sessionState.use(writer::bytes)
            plaintext.use(writer::bytes)
            writer.uint(capabilities).uint(mode.wireValue.toLong())
            writer.finish()
        }
        return invoke(OP_ENCRYPT, request) { payload ->
            payload.array(3)
            val nextState = payload.bytes(MAX_SESSION_STATE)
            try {
                val messageId = payload.bytes(16)
                val count = payload.arrayLength()
                require(count in 1..MAX_PARTS)
                val parts = List(count) { payload.ascii(MAX_PART) }
                payload.finish()
                EncryptionPrepared(OwnedSecret.takeOwnership(nextState), messageId, parts)
            } catch (error: Throwable) {
                nextState.fill(0)
                throw error
            }
        }
    }

    fun decrypt(sessionState: OwnedSecret, parts: List<String>): DecryptionPrepared {
        require(parts.size in 1..MAX_PARTS)
        val request = CborWriter().use { writer ->
            writer.array(3).uint(WIRE_VERSION.toLong())
            sessionState.use(writer::bytes)
            writer.array(parts.size)
            parts.forEach(writer::ascii)
            writer.finish()
        }
        return invoke(OP_DECRYPT, request) { payload ->
            payload.array(3)
            val nextState = payload.bytes(MAX_SESSION_STATE)
            var plaintext: ByteArray? = null
            try {
                val messageId = payload.bytes(16)
                plaintext = payload.bytes(MAX_PLAINTEXT_BYTES)
                payload.finish()
                DecryptionPrepared(
                    OwnedSecret.takeOwnership(nextState),
                    messageId,
                    OwnedSecret.takeOwnership(plaintext),
                )
            } catch (error: Throwable) {
                nextState.fill(0)
                plaintext?.fill(0)
                throw error
            }
        }
    }

    fun parseEnvelope(part: String): EnvelopeMetadata {
        val request = CborWriter().use { writer ->
            writer.array(2).uint(WIRE_VERSION.toLong()).ascii(part).finish()
        }
        return invoke(OP_PARSE_ENVELOPE, request) { payload ->
            payload.array(7)
            val result = EnvelopeMetadata(
                routingTag = payload.bytes(16),
                messageId = payload.bytes(16),
                partNumber = payload.uint().toInt(),
                totalParts = payload.uint().toInt(),
                capabilities = payload.uint(),
                olmType = payload.uint().toInt(),
                payloadBytes = payload.uint(),
            )
            payload.finish()
            result
        }
    }

    fun encodePresentation(parts: List<String>, presentation: TransportPresentation): String {
        require(parts.size in 1..MAX_PARTS)
        val request = CborWriter().use { writer ->
            writer.array(3).uint(WIRE_VERSION.toLong()).uint(presentation.wireValue.toLong())
            writer.array(parts.size)
            parts.forEach(writer::ascii)
            writer.finish()
        }
        return invoke(OP_ENCODE_PRESENTATION, request) { payload ->
            payload.array(1)
            val result = payload.utf8(MAX_PRESENTATION_TEXT_BYTES)
            payload.finish()
            result
        }
    }

    fun decodePresentation(text: String): PresentationDecoded {
        require(text.isNotEmpty())
        require(text.length <= MAX_PRESENTATION_TEXT_BYTES)
        val request = CborWriter().use { writer ->
            writer.array(2).uint(WIRE_VERSION.toLong()).utf8(text, MAX_PRESENTATION_TEXT_BYTES).finish()
        }
        return invoke(OP_DECODE_PRESENTATION, request) { payload ->
            payload.array(2)
            val presentation = TransportPresentation.fromWire(payload.uint().toInt())
            val count = payload.arrayLength()
            require(count in 1..MAX_PARTS)
            val parts = List(count) { payload.ascii(MAX_PART) }
            payload.finish()
            PresentationDecoded(presentation, parts)
        }
    }

    fun parsePairingPayload(
        qrPayload: ByteArray,
        nowEpochSeconds: Long,
    ): PairingPayloadMetadata {
        require(nowEpochSeconds >= 0)
        val request = CborWriter().use { writer ->
            writer.array(3).uint(WIRE_VERSION.toLong()).bytes(qrPayload).uint(nowEpochSeconds).finish()
        }
        return invoke(OP_PARSE_PAIRING_PAYLOAD, request) { payload ->
            payload.array(10)
            val type = PairingPayloadType.fromWire(payload.uint().toInt())
            val pairingId = payload.bytes(16)
            val remote = payload.identity()
            val remoteFingerprint = payload.bytes(32)
            val nonce = payload.bytes(32)
            val capabilities = payload.uint()
            val expiresAt = payload.uint().let { if (it == 0L) null else it }
            val expired = payload.uint().also { require(it in 0..1) } == 1L
            val offerHash = payload.bytes(32)
            payload.finish()
            PairingPayloadMetadata(
                type = type,
                pairingId = pairingId,
                remoteIdentity = remote,
                remoteIdentityFingerprint = remoteFingerprint,
                nonce = nonce,
                capabilities = capabilities,
                expiresAtEpochSeconds = expiresAt,
                status = if (expired) PairingPayloadStatus.EXPIRED else PairingPayloadStatus.VALID,
                offerHash = offerHash,
            )
        }
    }

    private fun <T> invoke(operation: Int, request: ByteArray, decode: (CborReader) -> T): T {
        val response = try {
            NativeBridge.nativeInvoke(operation, request)
        } finally {
            request.fill(0)
        }
        var payloadBytes: ByteArray? = null
        try {
            val responseReader = CborReader(response)
            responseReader.array(3)
            require(responseReader.uint() == WIRE_VERSION.toLong())
            val status = responseReader.uint()
            payloadBytes = responseReader.bytes(MAX_WIRE_BYTES)
            responseReader.finish()
            if (status != 0L) throw CryptoCoreException(status.toInt())
            return decode(CborReader(payloadBytes))
        } finally {
            response.fill(0)
            payloadBytes?.fill(0)
        }
    }

    private fun request(fields: Int): ByteArray = CborWriter().use { writer ->
        writer.array(fields).uint(WIRE_VERSION.toLong()).finish()
    }

    private fun CborReader.identity(): PublicIdentity =
        PublicIdentity(bytes(32), bytes(32))

    private fun CborReader.safetyCode(): SafetyCode = SafetyCode(
        hash = bytes(32),
        decimalGroups = ascii(96),
        wordCode = ascii(128),
    )

    companion object {
        private const val OP_PROTOCOL = 0
        private const val OP_CREATE_ACCOUNT = 1
        private const val OP_CREATE_OFFER = 2
        private const val OP_RESPOND_OFFER = 3
        private const val OP_COMPLETE_PAIRING = 4
        private const val OP_ENCRYPT = 5
        private const val OP_DECRYPT = 6
        private const val OP_PARSE_ENVELOPE = 7
        private const val OP_PARSE_PAIRING_PAYLOAD = 8
        private const val OP_ENCODE_PRESENTATION = 9
        private const val OP_DECODE_PRESENTATION = 10

        private const val MAX_ACCOUNT_STATE = 1024 * 1024
        private const val MAX_SESSION_STATE = 4 * 1024 * 1024
        const val MAX_PLAINTEXT_BYTES = 192 * 1024
        private const val MAX_PAIRING = 32 * 1024
        private const val MAX_PART = 32 * 1024
        private const val MAX_PARTS = 128
        const val MAX_PRESENTATION_TEXT_BYTES = 768 * 1024
    }
}

internal object NativeBridge {
    init {
        System.loadLibrary("cipherboard_crypto_jni")
    }

    external fun nativeInvoke(operation: Int, request: ByteArray): ByteArray
}
