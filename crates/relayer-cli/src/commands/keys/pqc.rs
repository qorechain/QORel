//! `keys register-pqc` and `keys pqc-status`: the post-quantum key of a chain
//! with `signing = "qorechain-hybrid"`.

use abscissa_core::clap::Parser;
use abscissa_core::{Command, Runnable};
use eyre::eyre;
use prost::Message;
use serde_json::json;
use tendermint_rpc::HttpClient;

use ibc_proto::google::protobuf::Any;
use ibc_relayer::chain::cosmos::config::CosmosSdkConfig;
use ibc_relayer::chain::cosmos::pqc::{
    query_applied_plan_height, query_pqc_key_status, resolve_sign_bytes_version,
};
use ibc_relayer::chain::cosmos::tx::simple_send_tx;
use ibc_relayer::chain::cosmos::types::config::TxConfig;
use ibc_relayer::config::ChainConfig;
use ibc_relayer::keyring::pqc::{load_pqc_signer, public_key_sha256};
use ibc_relayer::keyring::{KeyRing, Secp256k1KeyPair, SigningKeyPair};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use qorel_signer::mldsa87::MlDsa87Signer;
use qorel_signer::qorechain::is_legacy_sign_bytes_chain;
use qorel_signer::qorechain::proto::MSG_REGISTER_PQC_KEY_V2_TYPE_URL;
use qorel_signer::qorechain::register::{register_msg, PROOF_OF_POSSESSION_UPGRADE};
use qorel_signer::PqSigner;

use crate::application::app_config;

/// Gas multiplier floor for the registration transaction.
const REGISTRATION_GAS_MULTIPLIER: f64 = 1.1;
use crate::conclude::Output;

/// `keys register-pqc --chain <CHAIN_ID> [--key-name <KEY_NAME>] [--no-proof]`
///
/// Sends `MsgRegisterPQCKeyV2` for the key's ML-DSA-87 public key. It is the
/// one transaction QoreChain accepts with the classical signature alone.
/// Idempotent: nothing is sent when the same key is already registered.
#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct KeysRegisterPqcCmd {
    #[clap(
        long = "chain",
        required = true,
        value_name = "CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the chain"
    )]
    chain_id: ChainId,

    #[clap(
        long = "key-name",
        value_name = "KEY_NAME",
        help = "(optional) name of the key (defaults to the `key_name` defined in the config)"
    )]
    key_name: Option<String>,

    #[clap(
        long = "no-proof",
        help = "(optional) register without a proof of possession (only for networks older than v3.2.3)"
    )]
    no_proof: bool,
}

/// `keys pqc-status --chain <CHAIN_ID> [--key-name <KEY_NAME>]`
#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct KeysPqcStatusCmd {
    #[clap(
        long = "chain",
        required = true,
        value_name = "CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the chain"
    )]
    chain_id: ChainId,

    #[clap(
        long = "key-name",
        value_name = "KEY_NAME",
        help = "(optional) name of the key (defaults to the `key_name` defined in the config)"
    )]
    key_name: Option<String>,
}

struct Ctx {
    config: CosmosSdkConfig,
    key_pair: Secp256k1KeyPair,
    pq: MlDsa87Signer,
    rpc: HttpClient,
    rt: tokio::runtime::Runtime,
}

fn context(chain_id: &ChainId, key_name: &Option<String>) -> eyre::Result<Ctx> {
    let app = app_config();
    let config = match app.find_chain(chain_id) {
        Some(ChainConfig::CosmosSdk(c)) => c.clone(),
        Some(_) => return Err(eyre!("chain '{chain_id}' is not a Cosmos SDK chain")),
        None => return Err(eyre!("chain '{chain_id}' not found in configuration file")),
    };
    if !config.signing.is_qorechain_hybrid() {
        return Err(eyre!(
            "chain '{chain_id}' does not use `signing = \"qorechain-hybrid\"`"
        ));
    }
    let key_name = key_name.clone().unwrap_or_else(|| config.key_name.clone());
    let keyring = KeyRing::new_secp256k1(
        config.key_store_type,
        &config.account_prefix,
        &config.id,
        &config.key_store_folder,
    )?;
    let key_pair = keyring.get_key(&key_name)?;
    let pq = load_pqc_signer(
        &config.id,
        &config.key_store_folder,
        &key_name,
        &key_pair.account(),
        config.pqc.sign_mode.into(),
    )?;
    let rpc = HttpClient::builder(config.rpc_addr.clone().try_into()?).build()?;
    let rt = tokio::runtime::Runtime::new()?;
    Ok(Ctx {
        config,
        key_pair,
        pq,
        rpc,
        rt,
    })
}

impl Runnable for KeysPqcStatusCmd {
    fn run(&self) {
        let result = (|| -> eyre::Result<serde_json::Value> {
            let ctx = context(&self.chain_id, &self.key_name)?;
            let account = ctx.key_pair.account();
            let status = ctx.rt.block_on(query_pqc_key_status(
                &ctx.rpc,
                &ctx.config.id,
                &account,
                ctx.pq.public_key(),
            ))?;
            let version = ctx
                .rt
                .block_on(resolve_sign_bytes_version(&ctx.rpc, &ctx.config.id))
                .map(|v| format!("{v:?}").to_lowercase())
                .unwrap_or_else(|e| format!("unknown ({e})"));
            Ok(json!({
                "chain_id": ctx.config.id.to_string(),
                "account": account,
                "local_public_key_sha256": public_key_sha256(ctx.pq.public_key()),
                "registered": status.registered,
                "matches_local_key": status.matches_local_key,
                "registered_public_key_sha256": status.registered_key_sha256,
                "possession_proven": status.possession_proven,
                "sign_bytes": version,
                "ready_to_relay": status.registered && status.matches_local_key,
            }))
        })();
        match result {
            Ok(v) => Output::success(v).exit(),
            Err(e) => Output::error(e).exit(),
        }
    }
}

impl Runnable for KeysRegisterPqcCmd {
    fn run(&self) {
        match self.register() {
            Ok(v) => Output::success(v).exit(),
            Err(e) => Output::error(e).exit(),
        }
    }
}

impl KeysRegisterPqcCmd {
    fn register(&self) -> eyre::Result<serde_json::Value> {
        let ctx = context(&self.chain_id, &self.key_name)?;
        let account = ctx.key_pair.account();
        let local_sha = public_key_sha256(ctx.pq.public_key());

        let before = ctx.rt.block_on(query_pqc_key_status(
            &ctx.rpc,
            &ctx.config.id,
            &account,
            ctx.pq.public_key(),
        ))?;
        if before.registered {
            if before.matches_local_key {
                return Ok(json!({
                    "account": account,
                    "public_key_sha256": local_sha,
                    "already_registered": true,
                }));
            }
            return Err(eyre!(
                "{account} already has a different post-quantum key registered (sha256 {}); \
                 nothing was sent",
                before.registered_key_sha256.unwrap_or_default()
            ));
        }

        // A network that predates proofs of possession refuses a registration
        // carrying one; chains born on a current binary verify it.
        let with_proof = !self.no_proof
            && (!is_legacy_sign_bytes_chain(ctx.config.id.as_str())
                || ctx.rt.block_on(query_applied_plan_height(
                    &ctx.rpc,
                    PROOF_OF_POSSESSION_UPGRADE,
                ))? > 0);

        let ecdsa_pubkey = ctx.key_pair.public_key.serialize().to_vec();
        let msg = register_msg(
            &ctx.pq,
            ctx.config.id.as_str(),
            &account,
            &ecdsa_pubkey,
            with_proof,
        )?;
        let any = Any {
            type_url: MSG_REGISTER_PQC_KEY_V2_TYPE_URL.to_string(),
            value: msg.encode_to_vec(),
        };

        // The registration is the one message QoreChain accepts with the
        // classical signature alone: send it without the co-signer.
        let mut tx_config = TxConfig::try_from(&ctx.config)?;
        // Nodes older than the integrated v3.2.5 build under-report this
        // message by about 5% in simulation; give the one-time registration a
        // margin that covers them.
        tx_config.gas_config.gas_multiplier = tx_config
            .gas_config
            .gas_multiplier
            .max(REGISTRATION_GAS_MULTIPLIER);
        ctx.rt.block_on(simple_send_tx(
            &ctx.rpc,
            &tx_config,
            &ctx.key_pair,
            vec![any],
        ))?;

        let after = ctx.rt.block_on(query_pqc_key_status(
            &ctx.rpc,
            &ctx.config.id,
            &account,
            ctx.pq.public_key(),
        ))?;
        if !(after.registered && after.matches_local_key) {
            return Err(eyre!(
                "the registration was committed but the chain does not report the key yet; \
                 check with `keys pqc-status --chain {}`",
                ctx.config.id
            ));
        }
        Ok(json!({
            "account": account,
            "public_key_sha256": local_sha,
            "already_registered": false,
            "proof_of_possession": with_proof,
            "possession_proven": after.possession_proven,
        }))
    }
}
