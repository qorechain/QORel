//! One-time registration of the relayer's post-quantum key on QoreChain.

use super::proto::MsgRegisterPqcKeyV2;
use crate::mldsa87::{ALGORITHM_ID, PUBLIC_KEY_LEN};
use crate::{PqSigner, SignerError};

/// Domain of the proof-of-possession sign bytes.
pub const PROOF_OF_POSSESSION_DOMAIN: &str = "qorechain-pqc-pop-v1";
/// The upgrade from which the chain verifies a proof of possession; a node
/// below it refuses a registration that carries one.
pub const PROOF_OF_POSSESSION_UPGRADE: &str = "v3.2.3";
/// The key type the relayer registers.
pub const KEY_TYPE_HYBRID: &str = "hybrid";

/// `"qorechain-pqc-pop-v1|<chain id>|<algorithm>|<account>|<hex(public key)>"`.
pub fn proof_of_possession_sign_bytes(
    chain_id: &str,
    algorithm_id: u32,
    account: &str,
    public_key: &[u8],
) -> Result<Vec<u8>, SignerError> {
    if chain_id.is_empty() || account.is_empty() {
        return Err(SignerError::Invalid(
            "proof of possession needs a chain id and an account".into(),
        ));
    }
    let mut out = format!("{PROOF_OF_POSSESSION_DOMAIN}|{chain_id}|{algorithm_id}|{account}|");
    for b in public_key {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out.into_bytes())
}

/// Builds the registration message for `signer`'s key, for `account`, whose
/// compressed secp256k1 key is `ecdsa_pubkey`. With `with_proof` the key
/// signs a proof of possession (only on networks at
/// [`PROOF_OF_POSSESSION_UPGRADE`] or later).
pub fn register_msg(
    signer: &dyn PqSigner,
    chain_id: &str,
    account: &str,
    ecdsa_pubkey: &[u8],
    with_proof: bool,
) -> Result<MsgRegisterPqcKeyV2, SignerError> {
    if signer.algorithm_id() != ALGORITHM_ID || signer.public_key().len() != PUBLIC_KEY_LEN {
        return Err(SignerError::Invalid(
            "only ML-DSA-87 keys are registered on QoreChain".into(),
        ));
    }
    if ecdsa_pubkey.len() != 33 || !matches!(ecdsa_pubkey[0], 2 | 3) {
        return Err(SignerError::Invalid(
            "the classical key must be a 33-byte compressed secp256k1 key".into(),
        ));
    }
    let proof_of_possession = if with_proof {
        let bytes =
            proof_of_possession_sign_bytes(chain_id, ALGORITHM_ID, account, signer.public_key())?;
        signer.sign(&bytes)?
    } else {
        Vec::new()
    };
    Ok(MsgRegisterPqcKeyV2 {
        sender: account.to_string(),
        public_key: signer.public_key().to_vec(),
        algorithm_id: ALGORITHM_ID,
        ecdsa_pubkey: ecdsa_pubkey.to_vec(),
        key_type: KEY_TYPE_HYBRID.to_string(),
        proof_of_possession,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mldsa87::{mldsa87_verify, MlDsa87Signer, PqSignMode};

    #[test]
    fn proof_of_possession_verifies_over_the_documented_bytes() {
        let signer = MlDsa87Signer::from_seed(&[7u8; 32], PqSignMode::Hedged);
        let pk = [2u8; 33];
        let msg = register_msg(&signer, "qorechain-diana", "qor1x", &pk, true).unwrap();
        let bytes =
            proof_of_possession_sign_bytes("qorechain-diana", 1, "qor1x", signer.public_key())
                .unwrap();
        assert!(bytes.starts_with(b"qorechain-pqc-pop-v1|qorechain-diana|1|qor1x|"));
        assert_eq!(
            bytes.len(),
            "qorechain-pqc-pop-v1|qorechain-diana|1|qor1x|".len() + 2 * 2592
        );
        assert!(mldsa87_verify(
            signer.public_key(),
            &bytes,
            &msg.proof_of_possession
        ));
        assert_eq!(msg.key_type, "hybrid");
        assert_eq!(msg.algorithm_id, 1);
    }

    #[test]
    fn no_proof_leaves_the_field_empty_and_bad_keys_are_refused() {
        let signer = MlDsa87Signer::from_seed(&[7u8; 32], PqSignMode::Hedged);
        let msg = register_msg(&signer, "c", "a", &[3u8; 33], false).unwrap();
        assert!(msg.proof_of_possession.is_empty());
        assert!(register_msg(&signer, "c", "a", &[4u8; 33], false).is_err());
        assert!(register_msg(&signer, "c", "a", &[2u8; 32], false).is_err());
        assert!(register_msg(&signer, "", "a", &[2u8; 33], true).is_err());
    }
}
