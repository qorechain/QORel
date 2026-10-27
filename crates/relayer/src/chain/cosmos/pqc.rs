//! Post-quantum co-signing for chains with `signing = "qorechain-hybrid"`.
//!
//! The chain runtime owns one [`PqcRuntime`]. It loads the relayer key's
//! ML-DSA-87 seed, installs the co-signer in the [`TxConfig`] used by every
//! transaction (simulation, batch sizing and broadcast alike), keeps the
//! sign-bytes version read from the chain's upgrade record fresh, and checks
//! before any transaction is sent that the key is registered on chain and is
//! the one the relayer holds. Every failure refuses to send: no fee is spent
//! on a transaction the chain would refuse.

use core::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use prost::Message;
use qorel_signer::mldsa87::{MlDsa87Signer, PqSignMode};
use qorel_signer::qorechain::proto::{
    QueryAppliedPlanRequest, QueryAppliedPlanResponse, QueryPqcAccountRequest,
    QueryPqcAccountResponse, QUERY_APPLIED_PLAN_PATH, QUERY_PQC_ACCOUNT_PATH,
};
use qorel_signer::qorechain::{
    is_legacy_sign_bytes_chain, version_for, QoreChainFramer, SignBytesVersion, VersionCell,
    SIGN_BYTES_V2_UPGRADES,
};
use qorel_signer::{
    PqExtensionSigner, PqSigner, RawAny, SignRequest, SignerError, TxExtensionSigner,
};
use sha2::{Digest, Sha256};
use tendermint_rpc::{Client, HttpClient};
use tracing::{info, warn};

use crate::chain::cosmos::config::{CosmosSdkConfig, PqcSignBytes};
use crate::error::Error;
use crate::keyring::pqc::load_pqc_signer;

/// How long a sign-bytes version read from the chain is trusted.
pub const VERSION_TTL: Duration = Duration::from_secs(60);
/// How long a successful registration check is trusted.
pub const PREFLIGHT_TTL: Duration = Duration::from_secs(600);

/// A co-signer that always refuses: installed when the post-quantum key could
/// not be loaded, so a classical-only transaction is never produced for a
/// chain that requires the hybrid signature.
#[derive(Debug)]
struct UnavailableSigner(String);

impl TxExtensionSigner for UnavailableSigner {
    fn extension_options(&self, _req: &SignRequest<'_>) -> Result<Vec<RawAny>, SignerError> {
        Err(SignerError::Signing(self.0.clone()))
    }
}

/// The registration state of an account's post-quantum key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqcKeyStatus {
    pub registered: bool,
    pub matches_local_key: bool,
    pub algorithm_id: u32,
    pub possession_proven: bool,
    pub registered_key_sha256: Option<String>,
}

pub struct PqcRuntime {
    chain_id: ChainId,
    account: String,
    mode: PqcSignBytes,
    version: VersionCell,
    version_checked_at: Option<Instant>,
    preflight_ok_at: Option<Instant>,
    public_key: Option<Vec<u8>>,
    load_error: Option<String>,
}

impl fmt::Debug for PqcRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqcRuntime")
            .field("chain_id", &self.chain_id)
            .field("account", &self.account)
            .field("version", &self.version.get())
            .field("key_loaded", &self.public_key.is_some())
            .finish_non_exhaustive()
    }
}

impl PqcRuntime {
    /// Loads the key of `account` and returns the runtime plus the co-signer
    /// to install in the transaction config. A missing or invalid key yields
    /// a co-signer that refuses every transaction, with the reason.
    pub fn new(config: &CosmosSdkConfig, account: &str) -> (Self, Arc<dyn TxExtensionSigner>) {
        let version = VersionCell::new();
        match config.pqc.sign_bytes {
            PqcSignBytes::V1 => version.set(SignBytesVersion::V1),
            PqcSignBytes::V2 => version.set(SignBytesVersion::V2),
            PqcSignBytes::Auto => {}
        }

        let mode: PqSignMode = config.pqc.sign_mode.into();
        let loaded = load_pqc_signer(
            &config.id,
            &config.key_store_folder,
            &config.key_name,
            account,
            mode,
        );

        let mut runtime = Self {
            chain_id: config.id.clone(),
            account: account.to_string(),
            mode: config.pqc.sign_bytes,
            version: version.clone(),
            version_checked_at: None,
            preflight_ok_at: None,
            public_key: None,
            load_error: None,
        };

        let signer: Arc<dyn TxExtensionSigner> = match loaded {
            Ok(pq) => {
                runtime.public_key = Some(pq.public_key().to_vec());
                Arc::new(build_signer(
                    pq,
                    config.id.as_str(),
                    version,
                    config.pqc.include_public_key,
                ))
            }
            Err(e) => {
                let reason = e.to_string();
                warn!("{reason}");
                runtime.load_error = Some(reason.clone());
                Arc::new(UnavailableSigner(reason))
            }
        };

        (runtime, signer)
    }

    /// Whether the version and the registration are known good; refreshes
    /// whatever is stale. Called before every transaction.
    pub async fn ensure_ready(&mut self, rpc: &HttpClient) -> Result<(), Error> {
        if let Some(reason) = &self.load_error {
            return Err(Error::pqc_signer(self.chain_id.clone(), reason.clone()));
        }
        self.refresh_version(rpc, false).await?;
        if self
            .preflight_ok_at
            .is_some_and(|at| at.elapsed() < PREFLIGHT_TTL)
        {
            return Ok(());
        }
        let status = self.status(rpc).await?;
        check_status(&self.chain_id, &self.account, &status)?;
        self.preflight_ok_at = Some(Instant::now());
        Ok(())
    }

    /// Reads the sign-bytes version from the chain (only for `auto`).
    pub async fn refresh_version(&mut self, rpc: &HttpClient, force: bool) -> Result<(), Error> {
        if self.mode != PqcSignBytes::Auto {
            return Ok(());
        }
        let fresh = self.version.get().is_some()
            && self
                .version_checked_at
                .is_some_and(|at| at.elapsed() < VERSION_TTL);
        if fresh && !force {
            return Ok(());
        }
        match resolve_sign_bytes_version(rpc, &self.chain_id).await {
            Ok(v) => {
                if self.version.get() != Some(v) {
                    info!(chain = %self.chain_id, "post-quantum sign bytes: {v:?}");
                }
                self.version.set(v);
                self.version_checked_at = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                // Keep a known version for a while rather than stop relaying
                // on one failed query; never invent one.
                if self.version.get().is_some()
                    && self
                        .version_checked_at
                        .is_some_and(|at| at.elapsed() < VERSION_TTL * 10)
                {
                    warn!(chain = %self.chain_id, "cannot refresh the sign-bytes version: {e}");
                    Ok(())
                } else {
                    self.version.clear();
                    Err(e)
                }
            }
        }
    }

    /// Forgets the cached version and registration check (after the chain
    /// refused a hybrid signature).
    pub fn invalidate(&mut self) {
        self.version_checked_at = None;
        self.preflight_ok_at = None;
    }

    /// The on-chain registration state of the relayer's key.
    pub async fn status(&self, rpc: &HttpClient) -> Result<PqcKeyStatus, Error> {
        let local = self.public_key.as_deref().unwrap_or_default();
        query_pqc_key_status(rpc, &self.chain_id, &self.account, local).await
    }
}

fn build_signer(
    pq: MlDsa87Signer,
    chain_id: &str,
    version: VersionCell,
    include_public_key: bool,
) -> PqExtensionSigner {
    PqExtensionSigner::new(
        Box::new(pq),
        Box::new(QoreChainFramer::new(chain_id, version)),
        include_public_key,
    )
}

/// Refuses to relay unless the key is registered and is ours.
pub fn check_status(chain_id: &ChainId, account: &str, status: &PqcKeyStatus) -> Result<(), Error> {
    if !status.registered {
        return Err(Error::pqc_signer(
            chain_id.clone(),
            format!(
                "{account} has no registered post-quantum key; register it first with \
                 `keys register-pqc --chain {chain_id}`"
            ),
        ));
    }
    if !status.matches_local_key {
        return Err(Error::pqc_signer(
            chain_id.clone(),
            format!(
                "{account} has a different post-quantum key registered on chain (sha256 {}); \
                 the relayer would be refused. Use the mnemonic that registered it, or rotate \
                 the key on chain",
                status.registered_key_sha256.as_deref().unwrap_or("unknown")
            ),
        ));
    }
    Ok(())
}

/// `cosmos.upgrade` applied height of `name` (0 when not applied).
pub async fn query_applied_plan_height(rpc: &HttpClient, name: &str) -> Result<i64, Error> {
    let req = QueryAppliedPlanRequest {
        name: name.to_string(),
    };
    let value = abci_query_raw(rpc, QUERY_APPLIED_PLAN_PATH, req.encode_to_vec()).await?;
    let resp = QueryAppliedPlanResponse::decode(value.as_slice()).map_err(|e| {
        Error::protobuf_decode("cosmos.upgrade.v1beta1.QueryAppliedPlanResponse".into(), e)
    })?;
    Ok(resp.height)
}

/// The hybrid sign-bytes version `chain_id` verifies, from its upgrade record.
pub async fn resolve_sign_bytes_version(
    rpc: &HttpClient,
    chain_id: &ChainId,
) -> Result<SignBytesVersion, Error> {
    if !is_legacy_sign_bytes_chain(chain_id.as_str()) {
        return Ok(SignBytesVersion::V2);
    }
    let mut best = 0;
    for name in SIGN_BYTES_V2_UPGRADES {
        let height = query_applied_plan_height(rpc, name).await?;
        if height > 0 {
            best = height;
            break;
        }
    }
    Ok(version_for(chain_id.as_str(), best))
}

/// The registration state of `account`'s post-quantum key, compared with
/// `local_public_key`.
pub async fn query_pqc_key_status(
    rpc: &HttpClient,
    chain_id: &ChainId,
    account: &str,
    local_public_key: &[u8],
) -> Result<PqcKeyStatus, Error> {
    let req = QueryPqcAccountRequest {
        address: account.to_string(),
    };
    let value = abci_query_raw(rpc, QUERY_PQC_ACCOUNT_PATH, req.encode_to_vec())
        .await
        .map_err(|e| {
            Error::pqc_signer(
                chain_id.clone(),
                format!("cannot read the post-quantum key of {account}: {e}"),
            )
        })?;
    let resp = QueryPqcAccountResponse::decode(value.as_slice())
        .map_err(|e| Error::protobuf_decode("qorechain.pqc.v1.QueryAccountResponse".into(), e))?;
    let view = resp.account.filter(|_| resp.found);
    Ok(match view {
        None => PqcKeyStatus {
            registered: false,
            matches_local_key: false,
            algorithm_id: 0,
            possession_proven: false,
            registered_key_sha256: None,
        },
        Some(v) => PqcKeyStatus {
            registered: true,
            matches_local_key: !local_public_key.is_empty() && v.public_key == local_public_key,
            algorithm_id: v.algorithm_id,
            possession_proven: v.possession_proven,
            registered_key_sha256: Some(hex::encode(Sha256::digest(&v.public_key))),
        },
    })
}

/// An `abci_query` with binary data, returning the value of a successful
/// answer.
pub async fn abci_query_raw(rpc: &HttpClient, path: &str, data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let response = rpc
        .abci_query(Some(path.to_string()), data, None, false)
        .await
        .map_err(|e| Error::other(format!("abci_query {path}: {e}")))?;
    if !response.code.is_ok() {
        return Err(Error::abci_query(response));
    }
    Ok(response.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(registered: bool, matches: bool) -> PqcKeyStatus {
        PqcKeyStatus {
            registered,
            matches_local_key: matches,
            algorithm_id: 1,
            possession_proven: true,
            registered_key_sha256: Some("ab".into()),
        }
    }

    #[test]
    fn preflight_refuses_unregistered_or_foreign_keys() {
        let chain = ChainId::from_string("qorechain-diana");
        assert!(check_status(&chain, "qor1x", &status(true, true)).is_ok());
        let err = check_status(&chain, "qor1x", &status(false, false)).unwrap_err();
        assert!(err.to_string().contains("register-pqc"), "{err}");
        let err = check_status(&chain, "qor1x", &status(true, false)).unwrap_err();
        assert!(
            err.to_string().contains("different post-quantum key"),
            "{err}"
        );
    }

    #[test]
    fn missing_key_installs_a_refusing_signer() {
        let signer = UnavailableSigner("no key".into());
        let req = SignRequest {
            chain_id: "qorechain-diana",
            body_without_ext: &[],
            auth_info: &[],
            account_number: 0,
            sequence: 0,
        };
        assert!(signer.extension_options(&req).is_err());
    }
}
