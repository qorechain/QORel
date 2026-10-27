//! Pluggable transaction co-signers for QORel.
//!
//! Some Cosmos SDK chains require more than the usual `SIGN_MODE_DIRECT`
//! secp256k1 signature: QoreChain, for example, refuses any transaction that
//! does not also carry an ML-DSA-87 (FIPS 204) signature in a critical
//! `TxBody` extension option. This crate is the chain-agnostic layer the
//! relayer calls while building a transaction:
//!
//! 1. the relayer encodes the body WITHOUT any co-signer extension (`B0`) and
//!    the final `AuthInfo` (fee, gas limit, sequence);
//! 2. a [`TxExtensionSigner`] turns `(chain id, B0, AuthInfo)` into the
//!    extension options to append to `TxBody.extension_options`;
//! 3. the relayer re-encodes the body with those options and makes the
//!    classical signature over the final body, as usual.
//!
//! A chain with standard signing simply has no co-signer, so the relayer's
//! transactions are unchanged.
//!
//! The crate works on raw protobuf bytes and depends on no IBC or relayer
//! types, so it can be embedded in any Rust relayer or tool. A new
//! post-quantum chain plugs in by providing a [`SignBytesFramer`] (how the
//! chain frames the signed message and packs the extension) and, if needed, a
//! new [`PqSigner`] primitive; [`PqExtensionSigner`] combines the two.

pub mod derive;
pub mod error;
pub mod mldsa87;
pub mod qorechain;

use core::fmt::Debug;

pub use error::SignerError;

/// A protobuf `google.protobuf.Any`, as raw parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawAny {
    /// The type URL, e.g. `/qorechain.pqc.v1.PQCHybridSignature`.
    pub type_url: String,
    /// The protobuf-encoded message.
    pub value: Vec<u8>,
}

/// Everything a co-signer may bind its signature to.
#[derive(Clone, Copy, Debug)]
pub struct SignRequest<'a> {
    /// The chain id the transaction is for.
    pub chain_id: &'a str,
    /// The encoded `TxBody` without any co-signer extension option.
    pub body_without_ext: &'a [u8],
    /// The final encoded `AuthInfo` (signer infos, fee, gas limit).
    pub auth_info: &'a [u8],
    /// The signer's account number.
    pub account_number: u64,
    /// The signer's sequence.
    pub sequence: u64,
}

/// A post-quantum signature primitive.
pub trait PqSigner: Send + Sync + Debug {
    /// The chain-level algorithm identifier (QoreChain: ML-DSA-87 = 1).
    fn algorithm_id(&self) -> u32;
    /// The encoded public key.
    fn public_key(&self) -> &[u8];
    /// Signs `msg` as-is (no pre-hashing).
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// How one chain frames the message its post-quantum key signs, and how it
/// carries the signature in the transaction.
pub trait SignBytesFramer: Send + Sync + Debug {
    /// Refuses a body the chain would not accept once the extension is added.
    fn check_body(&self, body_without_ext: &[u8]) -> Result<(), SignerError>;
    /// The exact bytes the post-quantum key signs.
    fn frame(&self, req: &SignRequest<'_>) -> Result<Vec<u8>, SignerError>;
    /// Packs a signature into the extension option `Any`.
    fn pack(
        &self,
        algorithm_id: u32,
        signature: Vec<u8>,
        public_key: Option<&[u8]>,
    ) -> Result<RawAny, SignerError>;
}

/// Produces the extension options a transaction needs before its classical
/// signature is made.
pub trait TxExtensionSigner: Send + Sync + Debug {
    /// The extension options to append to `TxBody.extension_options`, in order.
    fn extension_options(&self, req: &SignRequest<'_>) -> Result<Vec<RawAny>, SignerError>;
}

/// The generic co-signer: a [`PqSigner`] plus a chain's [`SignBytesFramer`].
#[derive(Debug)]
pub struct PqExtensionSigner {
    signer: Box<dyn PqSigner>,
    framer: Box<dyn SignBytesFramer>,
    include_public_key: bool,
}

impl PqExtensionSigner {
    /// Combines a primitive and a framer. With `include_public_key` the
    /// public key travels in every extension (larger transactions).
    pub fn new(
        signer: Box<dyn PqSigner>,
        framer: Box<dyn SignBytesFramer>,
        include_public_key: bool,
    ) -> Self {
        Self {
            signer,
            framer,
            include_public_key,
        }
    }

    /// The post-quantum public key this co-signer signs with.
    pub fn public_key(&self) -> &[u8] {
        self.signer.public_key()
    }
}

impl TxExtensionSigner for PqExtensionSigner {
    fn extension_options(&self, req: &SignRequest<'_>) -> Result<Vec<RawAny>, SignerError> {
        self.framer.check_body(req.body_without_ext)?;
        let msg = self.framer.frame(req)?;
        let signature = self.signer.sign(&msg)?;
        let public_key = self.include_public_key.then(|| self.signer.public_key());
        let ext = self
            .framer
            .pack(self.signer.algorithm_id(), signature, public_key)?;
        Ok(vec![ext])
    }
}
