//! QoreChain hybrid signing.
//!
//! QoreChain verifies, for every transaction, the classical secp256k1
//! signature AND an ML-DSA-87 signature carried as the single critical
//! extension option `/qorechain.pqc.v1.PQCHybridSignature`. The ML-DSA-87 key
//! signs the hybrid sign bytes (see [`hybrid_sign_bytes`]) over the body
//! without that option (`B0`) and the final `AuthInfo`. The chain re-derives
//! `B0` by decoding the received body, dropping the option and re-encoding
//! it, so `B0` must be canonical; [`body::check_body_policy`] enforces that
//! before anything is signed.

pub mod body;
pub mod proto;
pub mod register;
pub mod signbytes;

use prost::Message;

pub use signbytes::{
    hybrid_sign_bytes, is_hybrid_rejection, is_legacy_sign_bytes_chain, version_for,
    SignBytesVersion, VersionCell, LEGACY_SIGN_BYTES_CHAINS, SIGN_BYTES_V2_UPGRADES,
};

use crate::mldsa87::{MlDsa87Signer, PqSignMode, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::{PqExtensionSigner, RawAny, SignBytesFramer, SignRequest, SignerError};

/// The type URL of the hybrid signature extension option.
pub const HYBRID_SIG_TYPE_URL: &str = "/qorechain.pqc.v1.PQCHybridSignature";

/// `qorechain.pqc.v1.PQCHybridSignature`.
#[derive(Clone, PartialEq, Message)]
pub struct PqcHybridSignature {
    /// The algorithm id (ML-DSA-87 = 1).
    #[prost(uint32, tag = "1")]
    pub algorithm_id: u32,
    /// The raw signature.
    #[prost(bytes = "vec", tag = "2")]
    pub pqc_signature: Vec<u8>,
    /// The public key, optional (empty = absent).
    #[prost(bytes = "vec", tag = "3")]
    pub pqc_public_key: Vec<u8>,
}

/// Frames QoreChain hybrid sign bytes for one chain id.
#[derive(Clone, Debug)]
pub struct QoreChainFramer {
    chain_id: String,
    version: VersionCell,
}

impl QoreChainFramer {
    /// A framer for `chain_id`. On a legacy chain (`qorechain-vladi`,
    /// `qorechain-diana`) the sign-bytes version is read from `version`,
    /// which the relayer fills from the chain's upgrade record; until it is
    /// filled, signing is refused. Any other chain id signs v2.
    pub fn new(chain_id: impl Into<String>, version: VersionCell) -> Self {
        Self {
            chain_id: chain_id.into(),
            version,
        }
    }

    fn resolve(&self) -> Result<SignBytesVersion, SignerError> {
        if !is_legacy_sign_bytes_chain(&self.chain_id) {
            return Ok(SignBytesVersion::V2);
        }
        self.version.get().ok_or_else(|| {
            SignerError::SignBytesVersionUnknown(format!(
                "chain {} verifies sign-bytes v1 or v2 depending on its upgrade record \
                 ({}); it has not been read yet",
                self.chain_id,
                SIGN_BYTES_V2_UPGRADES.join(" or ")
            ))
        })
    }
}

impl SignBytesFramer for QoreChainFramer {
    fn check_body(&self, body_without_ext: &[u8]) -> Result<(), SignerError> {
        body::check_body_policy(body_without_ext)
    }

    fn frame(&self, req: &SignRequest<'_>) -> Result<Vec<u8>, SignerError> {
        if req.chain_id != self.chain_id {
            return Err(SignerError::Invalid(format!(
                "signer configured for {} asked to sign for {}",
                self.chain_id, req.chain_id
            )));
        }
        let version = self.resolve()?;
        Ok(hybrid_sign_bytes(
            version,
            req.chain_id,
            req.body_without_ext,
            req.auth_info,
        ))
    }

    fn pack(
        &self,
        algorithm_id: u32,
        signature: Vec<u8>,
        public_key: Option<&[u8]>,
    ) -> Result<RawAny, SignerError> {
        if algorithm_id != crate::mldsa87::ALGORITHM_ID {
            return Err(SignerError::Invalid(format!(
                "algorithm {algorithm_id} is not a QoreChain signature algorithm"
            )));
        }
        if signature.len() != SIGNATURE_LEN {
            return Err(SignerError::Invalid(format!(
                "ML-DSA-87 signature must be {SIGNATURE_LEN} bytes, got {}",
                signature.len()
            )));
        }
        if let Some(pk) = public_key {
            if pk.len() != PUBLIC_KEY_LEN {
                return Err(SignerError::Invalid(format!(
                    "ML-DSA-87 public key must be {PUBLIC_KEY_LEN} bytes, got {}",
                    pk.len()
                )));
            }
        }
        let value = PqcHybridSignature {
            algorithm_id,
            pqc_signature: signature,
            pqc_public_key: public_key.map(<[u8]>::to_vec).unwrap_or_default(),
        }
        .encode_to_vec();
        Ok(RawAny {
            type_url: HYBRID_SIG_TYPE_URL.to_string(),
            value,
        })
    }
}

/// The QoreChain co-signer: ML-DSA-87 from `seed` + [`QoreChainFramer`].
pub fn qorechain_hybrid_signer(
    chain_id: &str,
    seed: &[u8; 32],
    mode: PqSignMode,
    version: VersionCell,
    include_public_key: bool,
) -> PqExtensionSigner {
    PqExtensionSigner::new(
        Box::new(MlDsa87Signer::from_seed(seed, mode)),
        Box::new(QoreChainFramer::new(chain_id, version)),
        include_public_key,
    )
}
