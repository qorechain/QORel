//! ML-DSA-87 (FIPS 204) signing with the pure-Rust `fips204` crate.

use core::fmt;

use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

use crate::{PqSigner, SignerError};

/// ML-DSA-87 public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = ml_dsa_87::PK_LEN;
/// ML-DSA-87 signature length in bytes.
pub const SIGNATURE_LEN: usize = ml_dsa_87::SIG_LEN;
/// QoreChain's algorithm id for ML-DSA-87 (Dilithium-5).
pub const ALGORITHM_ID: u32 = 1;

/// FIPS 204 signing variant. Chains that verify FIPS 204 accept both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PqSignMode {
    /// Randomized ("hedged") signing, the FIPS 204 default. Each call differs.
    #[default]
    Hedged,
    /// Deterministic signing (`rnd` = 32 zero bytes): reproducible signatures,
    /// used for test vectors.
    Deterministic,
}

/// An ML-DSA-87 key pair derived from a 32-byte seed (FIPS 204
/// `KeyGen_internal(xi)`), with empty signing context.
///
/// The private key is zeroized on drop and never printed.
pub struct MlDsa87Signer {
    private_key: ml_dsa_87::PrivateKey,
    public_key: Vec<u8>,
    mode: PqSignMode,
}

impl MlDsa87Signer {
    /// Derives the key pair from `seed`.
    pub fn from_seed(seed: &[u8; 32], mode: PqSignMode) -> Self {
        let (pk, sk) = ml_dsa_87::KG::keygen_from_seed(seed);
        Self {
            private_key: sk,
            public_key: pk.into_bytes().to_vec(),
            mode,
        }
    }
}

impl fmt::Debug for MlDsa87Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87Signer")
            .field("public_key_prefix", &hex_prefix(&self.public_key))
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl PqSigner for MlDsa87Signer {
    fn algorithm_id(&self) -> u32 {
        ALGORITHM_ID
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignerError> {
        let sig = match self.mode {
            PqSignMode::Hedged => self.private_key.try_sign(msg, &[]),
            PqSignMode::Deterministic => self.private_key.try_sign_with_seed(&[0u8; 32], msg, &[]),
        }
        .map_err(|e| SignerError::Signing(e.to_string()))?;
        // Check our own output before it goes on chain: a faulty signature
        // would be refused after the fee is taken.
        if !mldsa87_verify(&self.public_key, msg, &sig) {
            return Err(SignerError::Signing(
                "produced signature does not verify".into(),
            ));
        }
        Ok(sig.to_vec())
    }
}

/// Verifies an ML-DSA-87 signature; any length other than exactly
/// [`PUBLIC_KEY_LEN`] / [`SIGNATURE_LEN`] is invalid.
pub fn mldsa87_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <[u8; PUBLIC_KEY_LEN]>::try_from(public_key),
        <[u8; SIGNATURE_LEN]>::try_from(signature),
    ) else {
        return false;
    };
    match ml_dsa_87::PublicKey::try_from_bytes(pk) {
        Ok(pk) => pk.verify(msg, &sig, &[]),
        Err(_) => false,
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().take(8).fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
