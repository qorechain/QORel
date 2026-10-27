//! Per-chain transaction signing settings.

use serde_derive::{Deserialize, Serialize};

/// How a chain's transactions are signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningMode {
    /// One classical signature, exactly as Hermes signs (any Cosmos SDK chain).
    #[default]
    Standard,
    /// QoreChain: the classical signature plus an ML-DSA-87 (FIPS 204)
    /// signature in the `PQCHybridSignature` extension option.
    QorechainHybrid,
}

impl SigningMode {
    pub fn is_standard(&self) -> bool {
        *self == SigningMode::Standard
    }

    pub fn is_qorechain_hybrid(&self) -> bool {
        *self == SigningMode::QorechainHybrid
    }
}

/// Which hybrid sign-bytes form to sign.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PqcSignBytes {
    /// Read the chain's upgrade record (the default, and the only safe
    /// choice for a network that may still upgrade).
    #[default]
    Auto,
    /// Always the legacy form.
    V1,
    /// Always the domain-tagged, chain-bound form.
    V2,
}

/// FIPS 204 signing variant for the post-quantum signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PqcSignMode {
    /// Randomized signing (the FIPS 204 default).
    #[default]
    Hedged,
    /// Deterministic signing (reproducible signatures).
    Deterministic,
}

impl From<PqcSignMode> for qorel_signer::mldsa87::PqSignMode {
    fn from(mode: PqcSignMode) -> Self {
        match mode {
            PqcSignMode::Hedged => Self::Hedged,
            PqcSignMode::Deterministic => Self::Deterministic,
        }
    }
}

/// Options of the post-quantum co-signer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PqcOptions {
    #[serde(default)]
    pub sign_bytes: PqcSignBytes,
    #[serde(default)]
    pub sign_mode: PqcSignMode,
    /// Embed the 2592-byte public key in every signature extension.
    #[serde(default)]
    pub include_public_key: bool,
}

impl PqcOptions {
    pub fn is_default(&self) -> bool {
        *self == PqcOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde_derive::Deserialize)]
    struct Chain {
        #[serde(default)]
        signing: SigningMode,
        #[serde(default)]
        pqc: PqcOptions,
    }

    #[test]
    fn parses_signing_settings() {
        let c: Chain = toml::from_str("").unwrap();
        assert!(c.signing.is_standard());
        assert!(c.pqc.is_default());

        let c: Chain = toml::from_str(
            "signing = \"qorechain-hybrid\"\npqc = { sign_bytes = \"v2\", sign_mode = \"deterministic\" }",
        )
        .unwrap();
        assert!(c.signing.is_qorechain_hybrid());
        assert_eq!(c.pqc.sign_bytes, PqcSignBytes::V2);
        assert_eq!(c.pqc.sign_mode, PqcSignMode::Deterministic);
        assert!(!c.pqc.include_public_key);

        assert!(toml::from_str::<Chain>("signing = \"hybrid\"").is_err());
        assert!(toml::from_str::<Chain>("pqc = { typo = 1 }").is_err());
    }
}
