//! The QoreChain and Cosmos SDK protobuf messages the relayer needs around
//! hybrid signing: key registration, the PQC account query, the upgrade
//! record query that decides the sign-bytes version, and the EVM fee market's
//! base fee. Plain prost structs, so the crate stays free of generated code.

use prost::Message;

/// `/qorechain.pqc.v1.MsgRegisterPQCKeyV2`.
pub const MSG_REGISTER_PQC_KEY_V2_TYPE_URL: &str = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2";
/// gRPC path of the PQC account query.
pub const QUERY_PQC_ACCOUNT_PATH: &str = "/qorechain.pqc.v1.Query/Account";
/// gRPC path of the applied upgrade plan query.
pub const QUERY_APPLIED_PLAN_PATH: &str = "/cosmos.upgrade.v1beta1.Query/AppliedPlan";
/// gRPC path of the EVM fee market base fee query.
pub const QUERY_EVM_BASE_FEE_PATH: &str = "/cosmos.evm.feemarket.v1.Query/BaseFee";

/// `qorechain.pqc.v1.MsgRegisterPQCKeyV2`.
#[derive(Clone, PartialEq, Message)]
pub struct MsgRegisterPqcKeyV2 {
    /// The account registering the key.
    #[prost(string, tag = "1")]
    pub sender: String,
    /// The post-quantum public key.
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: Vec<u8>,
    /// The algorithm id (ML-DSA-87 = 1).
    #[prost(uint32, tag = "3")]
    pub algorithm_id: u32,
    /// The account's compressed secp256k1 key.
    #[prost(bytes = "vec", tag = "4")]
    pub ecdsa_pubkey: Vec<u8>,
    /// The key type tag ("hybrid").
    #[prost(string, tag = "5")]
    pub key_type: String,
    /// Optional proof that the registrant holds the secret key (v3.2.3+).
    #[prost(bytes = "vec", tag = "6")]
    pub proof_of_possession: Vec<u8>,
}

/// `qorechain.pqc.v1.QueryAccountRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct QueryPqcAccountRequest {
    /// Bech32 account.
    #[prost(string, tag = "1")]
    pub address: String,
}

/// `qorechain.pqc.v1.QueryAccountResponse`.
#[derive(Clone, PartialEq, Message)]
pub struct QueryPqcAccountResponse {
    /// Whether the account has a registered key.
    #[prost(bool, tag = "1")]
    pub found: bool,
    /// The registered key, when found.
    #[prost(message, optional, tag = "2")]
    pub account: Option<PqcAccountView>,
}

/// `qorechain.pqc.v1.PQCAccountView` (the fields the relayer reads).
#[derive(Clone, PartialEq, Message)]
pub struct PqcAccountView {
    /// Bech32 account.
    #[prost(string, tag = "1")]
    pub address: String,
    /// Registered public key.
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: Vec<u8>,
    /// Algorithm id.
    #[prost(uint32, tag = "3")]
    pub algorithm_id: u32,
    /// Whether the key was proven by a proof of possession.
    #[prost(bool, tag = "11")]
    pub possession_proven: bool,
}

/// `cosmos.upgrade.v1beta1.QueryAppliedPlanRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct QueryAppliedPlanRequest {
    /// Upgrade name.
    #[prost(string, tag = "1")]
    pub name: String,
}

/// `cosmos.upgrade.v1beta1.QueryAppliedPlanResponse`.
#[derive(Clone, PartialEq, Message)]
pub struct QueryAppliedPlanResponse {
    /// Height at which the plan was applied, 0 when it was not.
    #[prost(int64, tag = "1")]
    pub height: i64,
}

/// `cosmos.evm.feemarket.v1.QueryBaseFeeResponse`.
#[derive(Clone, PartialEq, Message)]
pub struct QueryEvmBaseFeeResponse {
    /// The base fee as a decimal (`LegacyDec`, encoded as an 18-decimal
    /// fixed-point integer string).
    #[prost(string, tag = "1")]
    pub base_fee: String,
}

/// Parses a `LegacyDec` as it travels in protobuf (an integer string scaled
/// by 10^18), or as a plain decimal string ("0.1").
pub fn parse_legacy_dec(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains('.') {
        return s.parse::<f64>().ok().filter(|v| v.is_finite() && *v >= 0.0);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let padded = format!("{s:0>19}");
    let (int, frac) = padded.split_at(padded.len() - 18);
    format!("{int}.{frac}").parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_dec_parsing() {
        assert_eq!(parse_legacy_dec("100000000000000000"), Some(0.1));
        assert_eq!(parse_legacy_dec("1000000000000000000"), Some(1.0));
        assert_eq!(parse_legacy_dec("2500000000000000000"), Some(2.5));
        assert_eq!(parse_legacy_dec("0.100000000000000000"), Some(0.1));
        assert_eq!(parse_legacy_dec("0"), Some(0.0));
        assert_eq!(parse_legacy_dec(""), None);
        assert_eq!(parse_legacy_dec("abc"), None);
        assert_eq!(parse_legacy_dec("-1"), None);
    }

    #[test]
    fn diana_base_fee_answer_decodes() {
        // abci_query value returned by the diana testnet on 2026-10-27.
        let raw = b"\n\x12100000000000000000";
        let resp = QueryEvmBaseFeeResponse::decode(&raw[..]).unwrap();
        assert_eq!(parse_legacy_dec(&resp.base_fee), Some(0.1));
    }
}
