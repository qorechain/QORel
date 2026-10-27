//! QoreChain post-quantum key derivation from a mnemonic.
//!
//! QoreChain wallets bind the ML-DSA-87 key to the account ("adapter"
//! derivation): `seed = SHAKE256("qorechain:pqc:v1|" + address + "|" +
//! mnemonic)[..32]`, then FIPS 204 `KeyGen_internal(seed)`, where `address`
//! is the account in lower-case `qor1...` bech32. Any encoding of the same
//! 20-byte account (upper-case bech32, `0x` hex) resolves to that form first,
//! byte-identical to the QoreChain SDKs.

use bech32::{FromBase32, ToBase32, Variant};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroizing;

use crate::SignerError;

/// The account prefix QoreChain uses.
pub const QOR_PREFIX: &str = "qor";

/// Resolves `account` (bech32 with any prefix in one case, or `0x` hex) to
/// its canonical lower-case `qor1...` form.
pub fn canonical_qor_address(account: &str) -> Result<String, SignerError> {
    let payload = if let Some(hex) = account
        .strip_prefix("0x")
        .or_else(|| account.strip_prefix("0X"))
    {
        decode_hex(hex)?
    } else {
        let (_, data, variant) = bech32::decode(account)
            .map_err(|e| SignerError::Invalid(format!("invalid bech32 address: {e}")))?;
        if variant != Variant::Bech32 {
            return Err(SignerError::Invalid(
                "address is not bech32 (bech32m given)".into(),
            ));
        }
        Vec::<u8>::from_base32(&data)
            .map_err(|e| SignerError::Invalid(format!("invalid bech32 payload: {e}")))?
    };
    if payload.len() != 20 {
        return Err(SignerError::Invalid(format!(
            "account must be 20 bytes, got {}",
            payload.len()
        )));
    }
    bech32::encode(QOR_PREFIX, payload.to_base32(), Variant::Bech32)
        .map_err(|e| SignerError::Invalid(format!("cannot encode address: {e}")))
}

/// The 32-byte ML-DSA-87 seed for `account` and `mnemonic` (adapter
/// derivation). The mnemonic is hashed as given; pass it normalised the way
/// the wallet that registered the key did (single spaces, lower case).
pub fn derive_pqc_seed(account: &str, mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    let canonical = canonical_qor_address(account)?;
    let mut hasher = Shake256::default();
    hasher.update(b"qorechain:pqc:v1|");
    hasher.update(canonical.as_bytes());
    hasher.update(b"|");
    hasher.update(mnemonic.as_bytes());
    let mut seed = Zeroizing::new([0u8; 32]);
    hasher.finalize_xof().read(seed.as_mut());
    Ok(seed)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, SignerError> {
    if s.len() % 2 != 0 {
        return Err(SignerError::Invalid("odd-length hex address".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| SignerError::Invalid("invalid hex address".into()))
        })
        .collect()
}
