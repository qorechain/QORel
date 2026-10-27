//! Byte-for-byte checks against vectors produced by the QoreChain chain code
//! itself (v3.2.5 x/pqc body stripping, v2 sign bytes, tx decoder and ante
//! handler) and against the public `qorechain-pqc` sign-bytes KAT.

use prost::Message;
use qorel_signer::mldsa87::{mldsa87_verify, MlDsa87Signer, PqSignMode};
use qorel_signer::qorechain::{
    body::{check_body_policy, strip_pqc_extension},
    hybrid_sign_bytes, qorechain_hybrid_signer, QoreChainFramer, SignBytesVersion, VersionCell,
    HYBRID_SIG_TYPE_URL,
};
use qorel_signer::{PqSigner, SignBytesFramer, SignRequest, TxExtensionSigner};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct TxBody {
    #[prost(message, repeated, tag = "1")]
    messages: Vec<Any>,
    #[prost(string, tag = "2")]
    memo: String,
    #[prost(uint64, tag = "3")]
    timeout_height: u64,
    #[prost(message, repeated, tag = "1023")]
    extension_options: Vec<Any>,
    #[prost(message, repeated, tag = "2047")]
    non_critical_extension_options: Vec<Any>,
}

#[derive(Clone, PartialEq, Message)]
struct SignDoc {
    #[prost(bytes = "vec", tag = "1")]
    body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    auth_info_bytes: Vec<u8>,
    #[prost(string, tag = "3")]
    chain_id: String,
    #[prost(uint64, tag = "4")]
    account_number: u64,
}

#[derive(Clone, PartialEq, Message)]
struct TxRaw {
    #[prost(bytes = "vec", tag = "1")]
    body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    auth_info_bytes: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    signatures: Vec<Vec<u8>>,
}

fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("missing {key}"))).unwrap()
}

fn relay() -> Value {
    load("relay-signbytes-v3.2.5.json")
}

fn seed32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

fn vector_pqc_seed() -> [u8; 32] {
    seed32(&hx(&relay()["keys"], "mldsa87_seed_hex"))
}

fn v2_cell() -> VersionCell {
    let cell = VersionCell::new();
    cell.set(SignBytesVersion::V2);
    cell
}

#[test]
fn kat_hybrid_v2_framing() {
    let kat = load("signbytes-kat-v3.1.98.json");
    let cases = kat["hybrid_v2"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let got = hybrid_sign_bytes(
            SignBytesVersion::V2,
            c["chain_id"].as_str().unwrap(),
            &hx(c, "body_without_pqc_ext_hex"),
            &hx(c, "auth_info_hex"),
        );
        assert_eq!(
            hex::encode(got),
            c["sign_bytes_hex"].as_str().unwrap(),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn vector_keys_derive_from_seed() {
    let keys = &relay()["keys"];
    let signer = MlDsa87Signer::from_seed(&vector_pqc_seed(), PqSignMode::Deterministic);
    assert_eq!(signer.public_key(), hx(keys, "mldsa87_pub_hex").as_slice());
    assert_eq!(signer.algorithm_id(), 1);
}

#[test]
fn relay_vectors_strip_frame_and_pack() {
    let v = relay();
    let signer = MlDsa87Signer::from_seed(&vector_pqc_seed(), PqSignMode::Deterministic);
    let framer = QoreChainFramer::new("qorechain-diana", v2_cell());
    for c in v["relay_v2"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let body = hx(c, "body_bytes_hex");
        let b0 = hx(c, "body_without_pqc_ext_hex");
        let auth = hx(c, "auth_info_hex");
        assert_eq!(strip_pqc_extension(&body).unwrap(), b0, "{name}: B0");

        let req = SignRequest {
            chain_id: c["chain_id"].as_str().unwrap(),
            body_without_ext: &b0,
            auth_info: &auth,
            account_number: c["account_number"].as_u64().unwrap(),
            sequence: c["sequence"].as_u64().unwrap(),
        };
        let msg = framer.frame(&req).unwrap();
        assert_eq!(
            hex::encode(&msg),
            c["sign_bytes_hex"].as_str().unwrap(),
            "{name}: sign bytes"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&msg)),
            c["sign_bytes_sha256"].as_str().unwrap(),
            "{name}"
        );

        let sig = signer.sign(&msg).unwrap();
        assert_eq!(
            hex::encode(&sig),
            c["pqc_signature_hex"].as_str().unwrap(),
            "{name}: sig"
        );
        let ext = framer.pack(1, sig, None).unwrap();
        assert_eq!(ext.type_url, HYBRID_SIG_TYPE_URL);
        assert_eq!(
            hex::encode(&ext.value),
            c["pqc_extension_value_hex"].as_str().unwrap(),
            "{name}: ext"
        );
    }
}

/// Rebuilds the accepted vectors end to end: the chain decoded these exact
/// TxRaw bytes and its full ante handler accepted them in delivery mode.
#[test]
fn accepted_relay_txs_rebuild_byte_for_byte() {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    let v = relay();
    let keys = &v["keys"];
    let classical = SigningKey::from_slice(&hx(keys, "secp256k1_priv_hex")).unwrap();
    let pq = qorechain_hybrid_signer(
        "qorechain-diana",
        &vector_pqc_seed(),
        PqSignMode::Deterministic,
        v2_cell(),
        false,
    );

    let accepted: Vec<&Value> = v["relay_v2"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["chain_checks"]["full_ante_deliver"] == "accepted")
        .collect();
    assert_eq!(accepted.len(), 2);

    for c in accepted {
        let name = c["name"].as_str().unwrap();
        let chain_id = c["chain_id"].as_str().unwrap();
        let b0 = hx(c, "body_without_pqc_ext_hex");
        let auth = hx(c, "auth_info_hex");
        let req = SignRequest {
            chain_id,
            body_without_ext: &b0,
            auth_info: &auth,
            account_number: c["account_number"].as_u64().unwrap(),
            sequence: c["sequence"].as_u64().unwrap(),
        };
        let exts = pq.extension_options(&req).unwrap();
        assert_eq!(exts.len(), 1);

        let mut body = TxBody::decode(b0.as_slice()).unwrap();
        body.extension_options = exts
            .into_iter()
            .map(|e| Any {
                type_url: e.type_url,
                value: e.value,
            })
            .collect();
        let body_bytes = body.encode_to_vec();
        assert_eq!(
            hex::encode(&body_bytes),
            c["body_bytes_hex"].as_str().unwrap(),
            "{name}: body"
        );

        let doc = SignDoc {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth.clone(),
            chain_id: chain_id.to_string(),
            account_number: c["account_number"].as_u64().unwrap(),
        }
        .encode_to_vec();
        assert_eq!(
            hex::encode(&doc),
            c["classical_sign_doc_hex"].as_str().unwrap(),
            "{name}"
        );
        let sig: Signature = classical.sign(&doc);
        let sig = sig.normalize_s().unwrap_or(sig).to_bytes().to_vec();
        assert_eq!(
            hex::encode(&sig),
            c["classical_signature_hex"].as_str().unwrap(),
            "{name}"
        );

        let raw = TxRaw {
            body_bytes,
            auth_info_bytes: auth,
            signatures: vec![sig],
        }
        .encode_to_vec();
        assert_eq!(
            hex::encode(&raw),
            c["tx_raw_hex"].as_str().unwrap(),
            "{name}: tx_raw"
        );
        assert_eq!(raw.len() as u64, c["tx_raw_len"].as_u64().unwrap());
    }
}

/// The chain refuses any critical extension option next to the PQC one, in
/// either order (vectors c1, c3); the signer refuses to sign such a body.
#[test]
fn bodies_with_other_extension_options_are_refused() {
    let v = relay();
    for c in v["relay_v2"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let b0 = hx(c, "body_without_pqc_ext_hex");
        let has_other = c["extension_options_type_urls"].as_array().unwrap().len() > 1;
        assert_eq!(check_body_policy(&b0).is_err(), has_other, "{name}");
    }
}

#[test]
fn hedged_signature_verifies() {
    let signer = MlDsa87Signer::from_seed(&vector_pqc_seed(), PqSignMode::Hedged);
    let a = signer.sign(b"qorel").unwrap();
    let b = signer.sign(b"qorel").unwrap();
    assert_ne!(a, b, "hedged signatures differ per call");
    assert!(mldsa87_verify(signer.public_key(), b"qorel", &a));
    assert!(!mldsa87_verify(signer.public_key(), b"other", &a));
    let mut long = a.clone();
    long.push(0);
    assert!(!mldsa87_verify(signer.public_key(), b"qorel", &long));
}

/// Until the relayer has read the upgrade record, a legacy chain is never
/// signed for (no silent v1 fallback); a chain born with v2 needs no read.
#[test]
fn legacy_chain_waits_for_the_version() {
    use qorel_signer::SignerError;

    let v = relay();
    let c = &v["relay_v2"][1];
    let b0 = hx(c, "body_without_pqc_ext_hex");
    let auth = hx(c, "auth_info_hex");
    let req = |chain_id| SignRequest {
        chain_id,
        body_without_ext: &b0,
        auth_info: &auth,
        account_number: 4242,
        sequence: 17,
    };

    let cell = VersionCell::new();
    let pq = qorechain_hybrid_signer(
        "qorechain-diana",
        &vector_pqc_seed(),
        PqSignMode::Hedged,
        cell.clone(),
        false,
    );
    let err = pq.extension_options(&req("qorechain-diana")).unwrap_err();
    assert!(
        matches!(err, SignerError::SignBytesVersionUnknown(_)),
        "{err}"
    );

    cell.set(SignBytesVersion::V2);
    assert_eq!(
        pq.extension_options(&req("qorechain-diana")).unwrap().len(),
        1
    );

    let err = pq.extension_options(&req("qorechain-vladi")).unwrap_err();
    assert!(matches!(err, SignerError::Invalid(_)), "{err}");

    let fresh = qorechain_hybrid_signer(
        "qorechain-devnet",
        &vector_pqc_seed(),
        PqSignMode::Hedged,
        VersionCell::new(),
        false,
    );
    assert_eq!(
        fresh
            .extension_options(&req("qorechain-devnet"))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn public_key_can_travel_in_the_extension() {
    use prost::Message as _;
    use qorel_signer::qorechain::PqcHybridSignature;

    let v = relay();
    let c = &v["relay_v2"][1];
    let b0 = hx(c, "body_without_pqc_ext_hex");
    let auth = hx(c, "auth_info_hex");
    let pq = qorechain_hybrid_signer(
        "qorechain-diana",
        &vector_pqc_seed(),
        PqSignMode::Hedged,
        v2_cell(),
        true,
    );
    let req = SignRequest {
        chain_id: "qorechain-diana",
        body_without_ext: &b0,
        auth_info: &auth,
        account_number: 4242,
        sequence: 17,
    };
    let ext = &pq.extension_options(&req).unwrap()[0];
    let decoded = PqcHybridSignature::decode(ext.value.as_slice()).unwrap();
    assert_eq!(decoded.pqc_public_key, pq.public_key());
    assert_eq!(decoded.pqc_signature.len(), 4627);
    let msg = hybrid_sign_bytes(SignBytesVersion::V2, "qorechain-diana", &b0, &auth);
    assert!(mldsa87_verify(
        pq.public_key(),
        &msg,
        &decoded.pqc_signature
    ));
}
