use core::fmt;

/// Stable, non-secret error codes used across the FFI boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ErrorCode {
    InvalidInput = 1,
    SizeLimit = 2,
    UnsupportedVersion = 3,
    InvalidEncoding = 4,
    MissingField = 5,
    DuplicateField = 6,
    UnknownMandatoryField = 7,
    InvalidSignature = 8,
    ExpiredOffer = 9,
    InvalidTranscript = 10,
    PairingAlreadyUsed = 11,
    CryptoFailure = 12,
    WrongContact = 13,
    Replay = 14,
    MissingPart = 15,
    InconsistentParts = 16,
    TooManyParts = 17,
    InvalidUtf8 = 18,
    InvalidState = 19,
    RandomFailure = 20,
}

/// A deliberately detail-free error safe to log.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CoreError {
    code: ErrorCode,
}

impl CoreError {
    pub(crate) const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> ErrorCode {
        self.code
    }
}

impl fmt::Debug for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CipherBoard crypto error {}", self.code as i32)
    }
}

impl std::error::Error for CoreError {}

impl From<ErrorCode> for CoreError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

pub type Result<T> = core::result::Result<T, CoreError>;
