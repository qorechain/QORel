//! On-disk storage of a relayer key's post-quantum seed.
//!
//! A chain with `signing = "qorechain-hybrid"` needs, next to the usual
//! secp256k1 key, the ML-DSA-87 key the account registered on chain. That key
//! is derived from the same mnemonic and account (see
//! [`qorel_signer::derive`]); only its 32-byte seed is stored, in
//! `<keystore>/<chain id>/keyring-test/<key name>.pqc` (JSON; not `.json`, so
//! the classical keyring never lists it), readable by the owner only. The seed is never logged or printed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use qorel_signer::derive::{canonical_qor_address, derive_pqc_seed};
use qorel_signer::mldsa87::{MlDsa87Signer, PqSignMode};
use qorel_signer::PqSigner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;

use super::disk_store_path;

/// File name suffix of a stored post-quantum seed.
pub const PQC_KEY_FILE_SUFFIX: &str = "pqc";
const KEY_FILE_TYPE: &str = "qorechain-pqc-seed";
const ALGORITHM: &str = "ml-dsa-87";
const DERIVATION: &str = "qorechain:pqc:v1";

#[derive(Serialize, Deserialize)]
struct PqcKeyFile {
    #[serde(rename = "type")]
    file_type: String,
    algorithm: String,
    derivation: String,
    address: String,
    public_key_sha256: String,
    seed: String,
}

/// What `keys add` reports about a stored post-quantum key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPqcKey {
    pub address: String,
    pub public_key_sha256: String,
}

/// Where the post-quantum seed of `key_name` lives.
pub fn pqc_key_path(
    chain_id: &ChainId,
    keystore_folder: &Option<PathBuf>,
    key_name: &str,
) -> Result<PathBuf, Error> {
    let folder = disk_store_path(chain_id.as_str(), keystore_folder).map_err(Error::key_base)?;
    Ok(folder.join(format!("{key_name}.{PQC_KEY_FILE_SUFFIX}")))
}

/// Derives the post-quantum key of `account` from `mnemonic` and stores its
/// seed for `key_name`, replacing any previous one.
pub fn store_pqc_key_from_mnemonic(
    chain_id: &ChainId,
    keystore_folder: &Option<PathBuf>,
    key_name: &str,
    account: &str,
    mnemonic: &str,
) -> Result<StoredPqcKey, Error> {
    let normalized = Zeroizing::new(normalize_mnemonic(mnemonic));
    let address = canonical_qor_address(account).map_err(|e| pqc_error(chain_id, e))?;
    let seed = derive_pqc_seed(&address, &normalized).map_err(|e| pqc_error(chain_id, e))?;
    let signer = MlDsa87Signer::from_seed(&seed, PqSignMode::Hedged);
    let public_key_sha256 = hex::encode(Sha256::digest(signer.public_key()));

    let file = PqcKeyFile {
        file_type: KEY_FILE_TYPE.to_string(),
        algorithm: ALGORITHM.to_string(),
        derivation: DERIVATION.to_string(),
        address: address.clone(),
        public_key_sha256: public_key_sha256.clone(),
        seed: hex::encode(*seed),
    };
    let json = Zeroizing::new(
        serde_json::to_string_pretty(&file)
            .map_err(|e| Error::other(format!("cannot encode the PQC key file: {e}")))?,
    );
    drop(file);

    let path = pqc_key_path(chain_id, keystore_folder, key_name)?;
    write_private(&path, json.as_bytes())?;

    Ok(StoredPqcKey {
        address,
        public_key_sha256,
    })
}

/// Loads the post-quantum signer of `key_name`, refusing a seed stored for
/// another account than `expected_account`.
pub fn load_pqc_signer(
    chain_id: &ChainId,
    keystore_folder: &Option<PathBuf>,
    key_name: &str,
    expected_account: &str,
    mode: PqSignMode,
) -> Result<MlDsa87Signer, Error> {
    let path = pqc_key_path(chain_id, keystore_folder, key_name)?;
    let contents = Zeroizing::new(fs::read_to_string(&path).map_err(|_| {
        pqc_msg(
            chain_id,
            format!(
                "no post-quantum key for key '{key_name}' ({}); add the key again with \
                 `keys add --mnemonic-file` so its ML-DSA-87 seed is derived",
                path.display()
            ),
        )
    })?);
    let file: PqcKeyFile = serde_json::from_str(&contents).map_err(|_| {
        pqc_msg(
            chain_id,
            format!("malformed PQC key file {}", path.display()),
        )
    })?;
    if file.file_type != KEY_FILE_TYPE || file.algorithm != ALGORITHM {
        return Err(pqc_msg(
            chain_id,
            format!("{} is not an ML-DSA-87 seed file", path.display()),
        ));
    }
    let expected = canonical_qor_address(expected_account).map_err(|e| pqc_error(chain_id, e))?;
    if file.address != expected {
        return Err(pqc_msg(
            chain_id,
            format!(
                "the PQC key file for '{key_name}' belongs to {}, not to {expected}",
                file.address
            ),
        ));
    }
    let seed_hex = Zeroizing::new(file.seed);
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(seed_hex.as_bytes(), seed.as_mut())
        .map_err(|_| pqc_msg(chain_id, format!("invalid seed in {}", path.display())))?;
    let signer = MlDsa87Signer::from_seed(&seed, mode);
    if hex::encode(Sha256::digest(signer.public_key())) != file.public_key_sha256 {
        return Err(pqc_msg(
            chain_id,
            format!("{} is corrupted (public key mismatch)", path.display()),
        ));
    }
    Ok(signer)
}

/// Removes the stored post-quantum seed of `key_name`, if any.
pub fn remove_pqc_key(
    chain_id: &ChainId,
    keystore_folder: &Option<PathBuf>,
    key_name: &str,
) -> Result<(), Error> {
    let path = pqc_key_path(chain_id, keystore_folder, key_name)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::other(format!(
            "cannot remove {}: {e}",
            path.display()
        ))),
    }
}

/// Hex SHA-256 of a public key: how keys are named in messages.
pub fn public_key_sha256(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// Single spaces between words, as wallets hash the phrase.
pub fn normalize_mnemonic(mnemonic: &str) -> String {
    mnemonic.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), Error> {
    let err = |e: std::io::Error| Error::other(format!("cannot write {}: {e}", path.display()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(err)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(err)?;
    }
    f.write_all(contents).map_err(err)?;
    f.sync_all().map_err(err)
}

fn pqc_error(chain_id: &ChainId, e: qorel_signer::SignerError) -> Error {
    Error::pqc_signer(chain_id.clone(), e.to_string())
}

fn pqc_msg(chain_id: &ChainId, reason: String) -> Error {
    Error::pqc_signer(chain_id.clone(), reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const ACCOUNT: &str = "qor1npvwllfr9dqr8erajqqr6s0vxnk2ak55am9g2c";
    const PUBKEY_SHA256: &str = "3d7bd2b98be09288b43a2fa18049789782d35c408f93099724417249707d1585";

    fn temp_folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qorel-pqc-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn store_then_load_round_trip() {
        let dir = temp_folder("roundtrip");
        let folder = Some(dir.clone());
        let chain = ChainId::from_string("qorechain-devnet");
        let messy = format!("  {}\n", MNEMONIC.replace(' ', "   "));
        let stored =
            store_pqc_key_from_mnemonic(&chain, &folder, "relayer", ACCOUNT, &messy).unwrap();
        assert_eq!(stored.address, ACCOUNT);
        assert_eq!(stored.public_key_sha256, PUBKEY_SHA256);

        let path = pqc_key_path(&chain, &folder, "relayer").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let signer =
            load_pqc_signer(&chain, &folder, "relayer", ACCOUNT, PqSignMode::Hedged).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(signer.public_key())),
            PUBKEY_SHA256
        );

        let err = load_pqc_signer(
            &chain,
            &folder,
            "relayer",
            "qor1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnrql8a",
            PqSignMode::Hedged,
        );
        assert!(err.is_err());

        remove_pqc_key(&chain, &folder, "relayer").unwrap();
        assert!(load_pqc_signer(&chain, &folder, "relayer", ACCOUNT, PqSignMode::Hedged).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
