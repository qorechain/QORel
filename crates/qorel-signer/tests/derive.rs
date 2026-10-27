//! Cross-language derivation vector shared by the QoreChain Go, Rust,
//! TypeScript, Python and Java SDKs.

use qorel_signer::derive::{canonical_qor_address, derive_pqc_seed};
use qorel_signer::mldsa87::{MlDsa87Signer, PqSignMode};
use qorel_signer::PqSigner;
use sha2::{Digest, Sha256};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const COSMOS: &str = "qor1npvwllfr9dqr8erajqqr6s0vxnk2ak55am9g2c";
const EVM: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const PUBKEY_SHA256: &str = "3d7bd2b98be09288b43a2fa18049789782d35c408f93099724417249707d1585";

#[test]
fn every_encoding_derives_the_sdk_key() {
    let inputs = [
        COSMOS.to_string(),
        COSMOS.to_uppercase(),
        EVM.to_string(),
        EVM.to_lowercase(),
        format!("0X{}", EVM[2..].to_uppercase()),
    ];
    for input in inputs {
        assert_eq!(canonical_qor_address(&input).unwrap(), COSMOS, "{input}");
        let seed = derive_pqc_seed(&input, MNEMONIC).unwrap();
        let signer = MlDsa87Signer::from_seed(&seed, PqSignMode::Deterministic);
        assert_eq!(
            hex::encode(Sha256::digest(signer.public_key())),
            PUBKEY_SHA256,
            "{input}"
        );
    }
}

#[test]
fn bad_accounts_are_refused() {
    let mixed = format!("Qor1{}", &COSMOS[4..]);
    for bad in ["qor1abc", mixed.as_str(), "0x1234", "0xzz", ""] {
        assert!(canonical_qor_address(bad).is_err(), "{bad}");
        assert!(derive_pqc_seed(bad, MNEMONIC).is_err(), "{bad}");
    }
}

#[test]
fn debug_output_never_shows_the_seed() {
    let seed = derive_pqc_seed(COSMOS, MNEMONIC).unwrap();
    let signer = MlDsa87Signer::from_seed(&seed, PqSignMode::Hedged);
    let shown = format!("{signer:?}");
    assert!(!shown.contains(&hex::encode(*seed)), "{shown}");
    assert!(shown.contains("MlDsa87Signer"));
}
