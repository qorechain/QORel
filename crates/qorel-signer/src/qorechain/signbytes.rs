//! The hybrid sign bytes and the rule that picks their version per chain.
//!
//! | version | message signed by the ML-DSA-87 key |
//! |---|---|
//! | v1 (legacy) | `BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A` |
//! | v2 | `"qorechain-pqc-hybrid-v2" ‖ BE64(len chainID) ‖ chainID ‖ BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A` |
//!
//! A network verifies exactly one form. `qorechain-vladi` and
//! `qorechain-diana` verify v1 until one of [`SIGN_BYTES_V2_UPGRADES`] is
//! applied on them and v2 after it; any other chain verifies v2 from genesis.
//! The relayer reads the upgrade record (`cosmos.upgrade.v1beta1` applied
//! plan) and stores the answer in a [`VersionCell`]; it never guesses.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// Domain tag that opens the v2 sign bytes.
pub const HYBRID_SIGN_BYTES_DOMAIN: &str = "qorechain-pqc-hybrid-v2";

/// Every upgrade name that switched a legacy network to v2 (mainnet took
/// `v3.2.0`, the testnet took `v3.1.98`); any one applied means v2.
pub const SIGN_BYTES_V2_UPGRADES: &[&str] = &["v3.2.0", "v3.1.98"];

/// Networks that predate v2 and switch only at one of the upgrades above.
pub const LEGACY_SIGN_BYTES_CHAINS: &[&str] = &["qorechain-vladi", "qorechain-diana"];

/// The chain's PQC module codespace and its "hybrid signature does not
/// verify" code.
pub const PQC_CODESPACE: &str = "pqc";
/// See [`PQC_CODESPACE`].
pub const PQC_HYBRID_VERIFY_FAILED_CODE: u32 = 21;
const PQC_HYBRID_VERIFY_FAILED_MESSAGE: &str = "hybrid PQC signature verification failed";

/// A concrete sign-bytes form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignBytesVersion {
    /// No domain tag, no chain id.
    V1,
    /// Domain-tagged and chain-bound.
    V2,
}

/// Whether `chain_id` is one of [`LEGACY_SIGN_BYTES_CHAINS`].
pub fn is_legacy_sign_bytes_chain(chain_id: &str) -> bool {
    LEGACY_SIGN_BYTES_CHAINS.contains(&chain_id)
}

/// The form to sign for `chain_id`, given the greatest height at which any of
/// [`SIGN_BYTES_V2_UPGRADES`] was applied there (`0` when none was).
pub fn version_for(chain_id: &str, v2_applied_height: i64) -> SignBytesVersion {
    if v2_applied_height > 0 || !is_legacy_sign_bytes_chain(chain_id) {
        SignBytesVersion::V2
    } else {
        SignBytesVersion::V1
    }
}

/// The hybrid sign bytes in the given form (`chain_id` is unused by v1).
pub fn hybrid_sign_bytes(
    version: SignBytesVersion,
    chain_id: &str,
    body_without_ext: &[u8],
    auth_info: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HYBRID_SIGN_BYTES_DOMAIN.len()
            + 16
            + chain_id.len()
            + body_without_ext.len()
            + auth_info.len(),
    );
    if version == SignBytesVersion::V2 {
        out.extend_from_slice(HYBRID_SIGN_BYTES_DOMAIN.as_bytes());
        out.extend_from_slice(&(chain_id.len() as u64).to_be_bytes());
        out.extend_from_slice(chain_id.as_bytes());
    }
    out.extend_from_slice(&(body_without_ext.len() as u32).to_be_bytes());
    out.extend_from_slice(body_without_ext);
    out.extend_from_slice(&(auth_info.len() as u32).to_be_bytes());
    out.extend_from_slice(auth_info);
    out
}

/// Whether a refusal `(codespace, code, log)` is the chain rejecting the
/// hybrid signature (`pqc` code 21): the cue to re-read the version once.
pub fn is_hybrid_rejection(codespace: &str, code: u32, log: &str) -> bool {
    (codespace == PQC_CODESPACE && code == PQC_HYBRID_VERIFY_FAILED_CODE)
        || log.contains(PQC_HYBRID_VERIFY_FAILED_MESSAGE)
}

/// A shared, lock-free slot holding the resolved version for one chain.
/// Cloning shares the slot. Empty until [`VersionCell::set`].
#[derive(Clone, Debug, Default)]
pub struct VersionCell(Arc<AtomicU8>);

impl VersionCell {
    /// An empty cell.
    pub fn new() -> Self {
        Self::default()
    }

    /// The resolved version, if any.
    pub fn get(&self) -> Option<SignBytesVersion> {
        match self.0.load(Ordering::Acquire) {
            1 => Some(SignBytesVersion::V1),
            2 => Some(SignBytesVersion::V2),
            _ => None,
        }
    }

    /// Stores the resolved version.
    pub fn set(&self, version: SignBytesVersion) {
        let v = match version {
            SignBytesVersion::V1 => 1,
            SignBytesVersion::V2 => 2,
        };
        self.0.store(v, Ordering::Release);
    }

    /// Forgets the version (the next signature waits for a fresh read).
    pub fn clear(&self) {
        self.0.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_rule_mirrors_the_chain() {
        assert_eq!(version_for("qorechain-vladi", 0), SignBytesVersion::V1);
        assert_eq!(
            version_for("qorechain-vladi", 2_981_742),
            SignBytesVersion::V2
        );
        assert_eq!(
            version_for("qorechain-diana", 5_746_000),
            SignBytesVersion::V2
        );
        assert_eq!(version_for("qorechain-devnet", 0), SignBytesVersion::V2);
    }

    #[test]
    fn v1_framing_has_no_domain() {
        let got = hybrid_sign_bytes(SignBytesVersion::V1, "ignored", b"ab", b"c");
        assert_eq!(got, [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c']);
    }

    #[test]
    fn rejection_detection() {
        assert!(is_hybrid_rejection("pqc", 21, ""));
        assert!(!is_hybrid_rejection("sdk", 21, ""));
        assert!(is_hybrid_rejection(
            "",
            0,
            "x: hybrid PQC signature verification failed"
        ));
    }

    #[test]
    fn version_cell_is_shared() {
        let a = VersionCell::new();
        let b = a.clone();
        assert_eq!(b.get(), None);
        a.set(SignBytesVersion::V2);
        assert_eq!(b.get(), Some(SignBytesVersion::V2));
        b.clear();
        assert_eq!(a.get(), None);
    }
}
