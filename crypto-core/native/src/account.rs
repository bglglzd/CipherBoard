use serde_json::from_slice;
use sha2::{Digest, Sha256};
use vodozemac::olm::{Account, AccountPickle};
use zeroize::Zeroize;

use crate::{CoreError, ErrorCode, Result, SecretBytes};

const ACCOUNT_STATE_MAGIC: &[u8; 4] = b"CBA1";
const MAX_ACCOUNT_STATE_BYTES: usize = 1024 * 1024;

/// Public Curve25519 and Ed25519 identity keys. Local display names are never
/// part of this identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicIdentity {
    curve25519: [u8; 32],
    ed25519: [u8; 32],
}

impl PublicIdentity {
    pub(crate) const fn new(curve25519: [u8; 32], ed25519: [u8; 32]) -> Self {
        Self {
            curve25519,
            ed25519,
        }
    }

    pub const fn curve25519(&self) -> &[u8; 32] {
        &self.curve25519
    }

    pub const fn ed25519(&self) -> &[u8; 32] {
        &self.ed25519
    }

    /// SHA-256 fingerprint over both public identity keys and a domain label.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"CipherBoard Identity v1\0");
        digest.update(self.curve25519);
        digest.update(self.ed25519);
        digest.finalize().into()
    }

    /// Symmetric, non-secret routing tag for a pair of identities.
    pub fn routing_tag(&self, other: &Self) -> [u8; 16] {
        let ours = [self.curve25519.as_slice(), self.ed25519.as_slice()].concat();
        let theirs = [other.curve25519.as_slice(), other.ed25519.as_slice()].concat();
        let (first, second) = if ours <= theirs {
            (ours, theirs)
        } else {
            (theirs, ours)
        };
        let mut digest = Sha256::new();
        digest.update(b"CipherBoard Routing v1\0");
        digest.update(first);
        digest.update(second);
        let hash: [u8; 32] = digest.finalize().into();
        hash[..16].try_into().unwrap_or([0_u8; 16])
    }
}

/// Owner identity and its one-time-key store.
pub struct CipherAccount {
    pub(crate) inner: Account,
}

impl CipherAccount {
    /// Generate a fresh local identity using vodozemac's operating-system RNG.
    pub fn new() -> Self {
        Self {
            inner: Account::new(),
        }
    }

    pub fn public_identity(&self) -> PublicIdentity {
        PublicIdentity::new(
            self.inner.curve25519_key().to_bytes(),
            *self.inner.ed25519_key().as_bytes(),
        )
    }

    /// Serialize sensitive account state. The returned bytes must be wrapped
    /// by Android Keystore-backed authenticated encryption before persistence.
    pub fn serialize_state(&self) -> Result<SecretBytes> {
        let mut payload = serde_json::to_vec(&self.inner.pickle())
            .map_err(|_| CoreError::new(ErrorCode::InvalidState))?;
        if payload.len() > MAX_ACCOUNT_STATE_BYTES.saturating_sub(ACCOUNT_STATE_MAGIC.len()) {
            payload.zeroize();
            return Err(ErrorCode::SizeLimit.into());
        }
        let mut output = Vec::with_capacity(ACCOUNT_STATE_MAGIC.len() + payload.len());
        output.extend_from_slice(ACCOUNT_STATE_MAGIC);
        output.extend_from_slice(&payload);
        payload.zeroize();
        Ok(SecretBytes::new(output))
    }

    /// Restore sensitive account state after authenticated storage decryption.
    pub fn deserialize_state(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= ACCOUNT_STATE_MAGIC.len()
            || bytes.len() > MAX_ACCOUNT_STATE_BYTES
            || bytes.get(..ACCOUNT_STATE_MAGIC.len()) != Some(ACCOUNT_STATE_MAGIC)
        {
            return Err(ErrorCode::InvalidState.into());
        }
        let pickle: AccountPickle = from_slice(&bytes[ACCOUNT_STATE_MAGIC.len()..])
            .map_err(|_| CoreError::new(ErrorCode::InvalidState))?;
        Ok(Self {
            inner: Account::from_pickle(pickle),
        })
    }
}

impl Default for CipherAccount {
    fn default() -> Self {
        Self::new()
    }
}
