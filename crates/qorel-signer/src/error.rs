use core::fmt;

/// Why a co-signer refused to produce an extension.
///
/// Messages never carry key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerError {
    /// The transaction body would be refused by the chain once signed.
    BodyPolicy(String),
    /// The signed-message form for this chain is not known yet.
    SignBytesVersionUnknown(String),
    /// The post-quantum primitive failed.
    Signing(String),
    /// Malformed input (bytes, lengths, addresses).
    Invalid(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::BodyPolicy(m) => write!(f, "transaction body refused: {m}"),
            SignerError::SignBytesVersionUnknown(m) => write!(f, "sign-bytes version unknown: {m}"),
            SignerError::Signing(m) => write!(f, "post-quantum signing failed: {m}"),
            SignerError::Invalid(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for SignerError {}
