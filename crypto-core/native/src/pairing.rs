use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use vodozemac::{
    olm::{OlmMessage, SessionConfig},
    Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature,
};

use crate::{
    CipherAccount, CipherSession, CoreError, ErrorCode, PublicIdentity, Result, PROTOCOL_VERSION,
};

const OFFER_PREFIX: &str = "CBP1:";
const RESPONSE_PREFIX: &str = "CBR1:";
const OFFER_BODY_FIELDS: u64 = 9;
const OFFER_FIELDS: u64 = 10;
const RESPONSE_BODY_FIELDS: u64 = 10;
const RESPONSE_FIELDS: u64 = 11;
const MAX_PAIRING_TEXT_BYTES: usize = 32 * 1024;
const PAIRING_NONCE_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Longest permitted lifetime of a physical pairing offer.
pub const MAX_OFFER_TTL_SECONDS: u64 = 15 * 60;

/// Signed, one-time QR offer. It contains public keys only.
pub struct PairingOffer {
    pairing_id: [u8; 16],
    identity: PublicIdentity,
    one_time_key: [u8; 32],
    capabilities: u32,
    expires_at: u64,
    nonce: [u8; PAIRING_NONCE_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl PairingOffer {
    pub const fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    pub const fn identity(&self) -> PublicIdentity {
        self.identity
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub const fn capabilities(&self) -> u32 {
        self.capabilities
    }

    /// Encode the signed offer for display as a QR code.
    pub fn encode_qr(&self) -> Result<String> {
        encode_text(OFFER_PREFIX, &self.encode_binary()?)
    }

    /// Strictly decode and authenticate an offer QR payload.
    pub fn decode_qr(text: &str) -> Result<Self> {
        let binary = decode_text(OFFER_PREFIX, text)?;
        Self::decode_binary(&binary)
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        encode_offer_body(
            self.pairing_id,
            self.identity,
            self.one_time_key,
            self.capabilities,
            self.expires_at,
            self.nonce,
        )
    }

    fn encode_binary(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(OFFER_FIELDS)
            .map_err(|_| ErrorCode::InvalidEncoding)?;
        encode_offer_values(
            &mut encoder,
            self.pairing_id,
            self.identity,
            self.one_time_key,
            self.capabilities,
            self.expires_at,
            self.nonce,
        )?;
        encoder
            .bytes(&self.signature)
            .map_err(|_| ErrorCode::InvalidEncoding)?;
        Ok(encoder.into_writer())
    }

    fn decode_binary(binary: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(binary);
        require_array(&mut decoder, OFFER_FIELDS)?;
        let version = decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)?;
        if version != PROTOCOL_VERSION {
            return Err(ErrorCode::UnsupportedVersion.into());
        }
        if decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)? != 1 {
            return Err(ErrorCode::InvalidInput.into());
        }
        let pairing_id = read_fixed::<16>(&mut decoder)?;
        let curve = read_fixed::<32>(&mut decoder)?;
        let ed = read_fixed::<32>(&mut decoder)?;
        let one_time_key = read_fixed::<32>(&mut decoder)?;
        let capabilities = decoder.u32().map_err(|_| ErrorCode::InvalidEncoding)?;
        let expires_at = decoder.u64().map_err(|_| ErrorCode::InvalidEncoding)?;
        let nonce = read_fixed::<PAIRING_NONCE_BYTES>(&mut decoder)?;
        let signature = read_fixed::<SIGNATURE_BYTES>(&mut decoder)?;
        require_end(&decoder, binary)?;

        let identity = PublicIdentity::new(curve, ed);
        let offer = Self {
            pairing_id,
            identity,
            one_time_key,
            capabilities,
            expires_at,
            nonce,
            signature,
        };
        verify_signature(
            identity,
            b"CipherBoard Pairing Offer v1\0",
            &offer.unsigned_bytes()?,
            signature,
        )?;
        Ok(offer)
    }

    fn transcript_hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode_binary()?).into())
    }
}

/// Signed QR response containing the first Olm pre-key message.
pub struct PairingResponse {
    pairing_id: [u8; 16],
    identity: PublicIdentity,
    offer_hash: [u8; 32],
    nonce: [u8; PAIRING_NONCE_BYTES],
    olm_type: u8,
    olm_payload: Vec<u8>,
    capabilities: u32,
    signature: [u8; SIGNATURE_BYTES],
}

impl PairingResponse {
    pub const fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    pub const fn identity(&self) -> PublicIdentity {
        self.identity
    }

    pub const fn capabilities(&self) -> u32 {
        self.capabilities
    }

    pub fn encode_qr(&self) -> Result<String> {
        encode_text(RESPONSE_PREFIX, &self.encode_binary()?)
    }

    pub fn decode_qr(text: &str) -> Result<Self> {
        let binary = decode_text(RESPONSE_PREFIX, text)?;
        Self::decode_binary(&binary)
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        encode_response_body(
            self.pairing_id,
            self.identity,
            self.offer_hash,
            self.nonce,
            self.olm_type,
            &self.olm_payload,
            self.capabilities,
        )
    }

    fn encode_binary(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(RESPONSE_FIELDS)
            .map_err(|_| ErrorCode::InvalidEncoding)?;
        encode_response_values(
            &mut encoder,
            self.pairing_id,
            self.identity,
            self.offer_hash,
            self.nonce,
            self.olm_type,
            &self.olm_payload,
            self.capabilities,
        )?;
        encoder
            .bytes(&self.signature)
            .map_err(|_| ErrorCode::InvalidEncoding)?;
        Ok(encoder.into_writer())
    }

    fn decode_binary(binary: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(binary);
        require_array(&mut decoder, RESPONSE_FIELDS)?;
        let version = decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)?;
        if version != PROTOCOL_VERSION {
            return Err(ErrorCode::UnsupportedVersion.into());
        }
        if decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)? != 2 {
            return Err(ErrorCode::InvalidInput.into());
        }
        let pairing_id = read_fixed::<16>(&mut decoder)?;
        let identity = PublicIdentity::new(
            read_fixed::<32>(&mut decoder)?,
            read_fixed::<32>(&mut decoder)?,
        );
        let offer_hash = read_fixed::<32>(&mut decoder)?;
        let nonce = read_fixed::<PAIRING_NONCE_BYTES>(&mut decoder)?;
        let olm_type = decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)?;
        let olm_payload = decoder
            .bytes()
            .map_err(|_| ErrorCode::InvalidEncoding)?
            .to_vec();
        if olm_type > 1 || olm_payload.is_empty() || olm_payload.len() > MAX_PAIRING_TEXT_BYTES {
            return Err(ErrorCode::SizeLimit.into());
        }
        let capabilities = decoder.u32().map_err(|_| ErrorCode::InvalidEncoding)?;
        let signature = read_fixed::<SIGNATURE_BYTES>(&mut decoder)?;
        require_end(&decoder, binary)?;
        let response = Self {
            pairing_id,
            identity,
            offer_hash,
            nonce,
            olm_type,
            olm_payload,
            capabilities,
            signature,
        };
        verify_signature(
            identity,
            b"CipherBoard Pairing Response v1\0",
            &response.unsigned_bytes()?,
            signature,
        )?;
        Ok(response)
    }
}

/// Full transcript confirmation representations.
#[derive(Clone, Eq, PartialEq)]
pub struct SafetyCode {
    hash: [u8; 32],
}

impl SafetyCode {
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Eight fixed-width groups cover all 256 transcript-hash bits.
    pub fn decimal_groups(&self) -> String {
        self.hash
            .chunks_exact(4)
            .map(|chunk| {
                let value = u32::from_be_bytes(chunk.try_into().unwrap_or([0_u8; 4]));
                format!("{value:010}")
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Short supplementary word code. The decimal code remains the full check.
    pub fn word_code(&self) -> String {
        const WORDS: [&str; 16] = [
            "amber", "birch", "cloud", "dawn", "elm", "frost", "glass", "harbor", "iris", "jade",
            "kite", "linen", "maple", "north", "opal", "pine",
        ];
        self.hash[..4]
            .iter()
            .flat_map(|byte| {
                [
                    WORDS[usize::from(byte >> 4)],
                    WORDS[usize::from(byte & 0x0f)],
                ]
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Result on the device that scanned an offer and produced a response QR.
pub struct PreparedPairingResponse {
    pub response: PairingResponse,
    pub session: CipherSession,
    pub safety_code: SafetyCode,
}

/// Result on the offer device after consuming its one-time key.
pub struct PairingCompletion {
    pub session: CipherSession,
    pub safety_code: SafetyCode,
    pub remote_identity: PublicIdentity,
}

impl CipherAccount {
    /// Generate a signed single-use offer. Persist the updated account state
    /// atomically with publishing the QR because it now contains the OTK.
    pub fn create_pairing_offer(
        &mut self,
        now_epoch_seconds: u64,
        ttl_seconds: u64,
        capabilities: u32,
    ) -> Result<PairingOffer> {
        if ttl_seconds == 0 || ttl_seconds > MAX_OFFER_TTL_SECONDS {
            return Err(ErrorCode::InvalidInput.into());
        }
        let expires_at = now_epoch_seconds
            .checked_add(ttl_seconds)
            .ok_or(ErrorCode::InvalidInput)?;
        let mut pairing_id = [0_u8; 16];
        let mut nonce = [0_u8; PAIRING_NONCE_BYTES];
        getrandom::getrandom(&mut pairing_id).map_err(|_| ErrorCode::RandomFailure)?;
        getrandom::getrandom(&mut nonce).map_err(|_| ErrorCode::RandomFailure)?;
        let generated = self.inner.generate_one_time_keys(1);
        let one_time_key = generated
            .created
            .first()
            .ok_or(ErrorCode::CryptoFailure)?
            .to_bytes();
        let identity = self.public_identity();
        let unsigned = encode_offer_body(
            pairing_id,
            identity,
            one_time_key,
            capabilities,
            expires_at,
            nonce,
        )?;
        let signature = self
            .inner
            .sign(signing_input(b"CipherBoard Pairing Offer v1\0", &unsigned))
            .to_bytes();
        Ok(PairingOffer {
            pairing_id,
            identity,
            one_time_key,
            capabilities,
            expires_at,
            nonce,
            signature,
        })
    }

    /// Verify an offer, create a v2 outbound Olm session, and produce a signed
    /// response with an encrypted transcript binder.
    pub fn respond_to_pairing_offer(
        &self,
        offer: &PairingOffer,
        now_epoch_seconds: u64,
        local_capabilities: u32,
    ) -> Result<PreparedPairingResponse> {
        validate_offer_time(offer, now_epoch_seconds)?;
        let mut response_nonce = [0_u8; PAIRING_NONCE_BYTES];
        getrandom::getrandom(&mut response_nonce).map_err(|_| ErrorCode::RandomFailure)?;
        let offer_hash = offer.transcript_hash()?;
        let handshake = encode_handshake(offer.pairing_id, offer_hash, response_nonce)?;
        let remote_curve = Curve25519PublicKey::from_bytes(*offer.identity.curve25519());
        let one_time_key = Curve25519PublicKey::from_bytes(offer.one_time_key);
        let live = self
            .inner
            .create_outbound_session(SessionConfig::version_2(), remote_curve, one_time_key)
            .map_err(|_| CoreError::new(ErrorCode::CryptoFailure))?;
        let mut session = CipherSession::from_live(live, self.public_identity(), offer.identity);
        let olm = session.encrypt_initial(&handshake)?;
        let (olm_type, olm_payload) = olm.to_parts();
        let olm_type = u8::try_from(olm_type).map_err(|_| ErrorCode::CryptoFailure)?;
        let capabilities = offer.capabilities & local_capabilities;
        let identity = self.public_identity();
        let unsigned = encode_response_body(
            offer.pairing_id,
            identity,
            offer_hash,
            response_nonce,
            olm_type,
            &olm_payload,
            capabilities,
        )?;
        let signature = self
            .inner
            .sign(signing_input(
                b"CipherBoard Pairing Response v1\0",
                &unsigned,
            ))
            .to_bytes();
        let response = PairingResponse {
            pairing_id: offer.pairing_id,
            identity,
            offer_hash,
            nonce: response_nonce,
            olm_type,
            olm_payload,
            capabilities,
            signature,
        };
        let safety_code = safety_code(offer, &response)?;
        Ok(PreparedPairingResponse {
            response,
            session,
            safety_code,
        })
    }

    /// Consume the OTK and validate the encrypted transcript. Calling this
    /// again after committing the returned account state fails as replay.
    pub fn complete_pairing(
        &mut self,
        offer: &PairingOffer,
        response: &PairingResponse,
        now_epoch_seconds: u64,
    ) -> Result<PairingCompletion> {
        validate_offer_time(offer, now_epoch_seconds)?;
        if response.pairing_id != offer.pairing_id
            || response.offer_hash != offer.transcript_hash()?
            || response.capabilities & !offer.capabilities != 0
        {
            return Err(ErrorCode::InvalidTranscript.into());
        }
        let olm = OlmMessage::from_parts(usize::from(response.olm_type), &response.olm_payload)
            .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?;
        let pre_key = match &olm {
            OlmMessage::PreKey(message) => message,
            OlmMessage::Normal(_) => return Err(ErrorCode::InvalidTranscript.into()),
        };
        let remote_curve = Curve25519PublicKey::from_bytes(*response.identity.curve25519());
        // Work on a private copy so an invalid transcript cannot consume the
        // one-time key in the caller's account state.
        let serialized = self.serialize_state()?;
        let mut next_account = Self::deserialize_state(serialized.expose())?;
        let inbound = next_account
            .inner
            .create_inbound_session(SessionConfig::version_2(), remote_curve, pre_key)
            .map_err(|error| {
                if matches!(
                    error,
                    vodozemac::olm::SessionCreationError::MissingOneTimeKey(_)
                ) {
                    CoreError::new(ErrorCode::PairingAlreadyUsed)
                } else {
                    CoreError::new(ErrorCode::CryptoFailure)
                }
            })?;
        verify_handshake(&inbound.plaintext, offer, response)?;
        let local_identity = next_account.public_identity();
        let session = CipherSession::from_live(inbound.session, local_identity, response.identity);
        self.inner = next_account.inner;
        Ok(PairingCompletion {
            session,
            safety_code: safety_code(offer, response)?,
            remote_identity: response.identity,
        })
    }
}

fn validate_offer_time(offer: &PairingOffer, now: u64) -> Result<()> {
    if now > offer.expires_at {
        Err(ErrorCode::ExpiredOffer.into())
    } else {
        Ok(())
    }
}

fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + body.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(body);
    input
}

fn verify_signature(
    identity: PublicIdentity,
    domain: &[u8],
    body: &[u8],
    signature: [u8; SIGNATURE_BYTES],
) -> Result<()> {
    let key = Ed25519PublicKey::from_slice(identity.ed25519())
        .map_err(|_| CoreError::new(ErrorCode::InvalidSignature))?;
    let signature = Ed25519Signature::from_slice(&signature)
        .map_err(|_| CoreError::new(ErrorCode::InvalidSignature))?;
    key.verify(&signing_input(domain, body), &signature)
        .map_err(|_| CoreError::new(ErrorCode::InvalidSignature))
}

fn safety_code(offer: &PairingOffer, response: &PairingResponse) -> Result<SafetyCode> {
    let mut digest = Sha256::new();
    digest.update(b"CipherBoard Safety v1\0");
    digest.update(offer.encode_binary()?);
    digest.update(response.encode_binary()?);
    Ok(SafetyCode {
        hash: digest.finalize().into(),
    })
}

fn encode_offer_body(
    pairing_id: [u8; 16],
    identity: PublicIdentity,
    one_time_key: [u8; 32],
    capabilities: u32,
    expires_at: u64,
    nonce: [u8; PAIRING_NONCE_BYTES],
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(OFFER_BODY_FIELDS)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encode_offer_values(
        &mut encoder,
        pairing_id,
        identity,
        one_time_key,
        capabilities,
        expires_at,
        nonce,
    )?;
    Ok(encoder.into_writer())
}

fn encode_offer_values(
    encoder: &mut Encoder<Vec<u8>>,
    pairing_id: [u8; 16],
    identity: PublicIdentity,
    one_time_key: [u8; 32],
    capabilities: u32,
    expires_at: u64,
    nonce: [u8; PAIRING_NONCE_BYTES],
) -> Result<()> {
    encoder
        .u8(PROTOCOL_VERSION)
        .and_then(|e| e.u8(1))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&pairing_id)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(identity.curve25519())
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(identity.ed25519())
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&one_time_key)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u32(capabilities)
        .and_then(|e| e.u64(expires_at))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&nonce)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_response_body(
    pairing_id: [u8; 16],
    identity: PublicIdentity,
    offer_hash: [u8; 32],
    nonce: [u8; PAIRING_NONCE_BYTES],
    olm_type: u8,
    olm_payload: &[u8],
    capabilities: u32,
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(RESPONSE_BODY_FIELDS)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encode_response_values(
        &mut encoder,
        pairing_id,
        identity,
        offer_hash,
        nonce,
        olm_type,
        olm_payload,
        capabilities,
    )?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn encode_response_values(
    encoder: &mut Encoder<Vec<u8>>,
    pairing_id: [u8; 16],
    identity: PublicIdentity,
    offer_hash: [u8; 32],
    nonce: [u8; PAIRING_NONCE_BYTES],
    olm_type: u8,
    olm_payload: &[u8],
    capabilities: u32,
) -> Result<()> {
    encoder
        .u8(PROTOCOL_VERSION)
        .and_then(|e| e.u8(2))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&pairing_id)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(identity.curve25519())
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(identity.ed25519())
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&offer_hash)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&nonce)
        .and_then(|e| e.u8(olm_type))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(olm_payload)
        .and_then(|e| e.u32(capabilities))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    Ok(())
}

fn encode_handshake(
    pairing_id: [u8; 16],
    offer_hash: [u8; 32],
    nonce: [u8; 32],
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|e| e.u8(PROTOCOL_VERSION))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&pairing_id)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&offer_hash)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&nonce)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    Ok(encoder.into_writer())
}

fn verify_handshake(
    plaintext: &[u8],
    offer: &PairingOffer,
    response: &PairingResponse,
) -> Result<()> {
    let mut decoder = Decoder::new(plaintext);
    require_array(&mut decoder, 4)?;
    if decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)? != PROTOCOL_VERSION
        || read_fixed::<16>(&mut decoder)? != offer.pairing_id
        || read_fixed::<32>(&mut decoder)? != response.offer_hash
        || read_fixed::<32>(&mut decoder)? != response.nonce
    {
        return Err(ErrorCode::InvalidTranscript.into());
    }
    require_end(&decoder, plaintext)
}

fn encode_text(prefix: &str, binary: &[u8]) -> Result<String> {
    let mut output = String::with_capacity(prefix.len() + binary.len().div_ceil(3) * 4);
    output.push_str(prefix);
    URL_SAFE_NO_PAD.encode_string(binary, &mut output);
    if output.len() > MAX_PAIRING_TEXT_BYTES {
        Err(ErrorCode::SizeLimit.into())
    } else {
        Ok(output)
    }
}

fn decode_text(prefix: &str, text: &str) -> Result<Vec<u8>> {
    if text.len() > MAX_PAIRING_TEXT_BYTES || !text.starts_with(prefix) {
        return Err(ErrorCode::InvalidInput.into());
    }
    let encoded = &text[prefix.len()..];
    if encoded.is_empty()
        || encoded
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-' && *byte != b'_')
    {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ErrorCode::InvalidEncoding.into())
}

fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<()> {
    if decoder.array().map_err(|_| ErrorCode::InvalidEncoding)? == Some(expected) {
        Ok(())
    } else {
        Err(ErrorCode::InvalidEncoding.into())
    }
}

fn require_end(decoder: &Decoder<'_>, input: &[u8]) -> Result<()> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(ErrorCode::InvalidEncoding.into())
    }
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N]> {
    decoder
        .bytes()
        .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?
        .try_into()
        .map_err(|_| ErrorCode::InvalidInput.into())
}
