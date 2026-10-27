# Running QORel

QORel is a Hermes-based IBC relayer. For any chain that signs the standard
way, configuration, keys and commands are exactly Hermes' (see the Hermes
guide in `guide/`). This page covers what is new: chains that require a
post-quantum co-signature, such as QoreChain.

The binary is `qorel` (a `hermes` binary with the same CLI is also built).

## QoreChain chain entry

```toml
[[chains]]
id = 'qorechain-vladi'                 # mainnet; testnet: 'qorechain-diana'
type = 'CosmosSdk'
rpc_addr = 'https://rpc.qore.host'
grpc_addr = 'https://<your QoreChain gRPC endpoint>'
event_source = { mode = 'push', url = 'wss://rpc.qore.host/websocket', batch_delay = '500ms' }
account_prefix = 'qor'
key_name = 'qorel'
store_prefix = 'ibc'
default_gas = 400000
max_gas = 6000000

# The QoreChain-specific part:
signing = 'qorechain-hybrid'
gas_price = { price = 0.1, denom = 'uqor' }
gas_multiplier = 1.15
dynamic_gas_price = { enabled = true, multiplier = 1.0, max = 10.0, backend = 'cosmos-evm-feemarket' }
# optional, defaults shown:
# pqc = { sign_bytes = 'auto', sign_mode = 'hedged', include_public_key = false }
```

- `signing = 'qorechain-hybrid'` adds the ML-DSA-87 (FIPS 204) signature to
  every transaction QORel sends to this chain. Omit it (or `'standard'`) for
  every other chain.
- `pqc.sign_bytes = 'auto'` reads the chain's upgrade record to pick the
  signed-message form and re-reads it every minute and after any refusal;
  keep it on `auto`.
- `pqc.sign_mode`: `hedged` (randomized, default) or `deterministic`; the
  chain accepts both.
- Static `extension_options` cannot be combined with hybrid signing (the
  config is refused): the post-quantum signature must be the only critical
  extension option.
- Gas: QoreChain charges the whole fee (`gas limit x price`), with no
  refund, so keep the multiplier tight. On nodes running the integrated
  v3.2.5 build (diana) or later, simulation matches delivery to a few hundred
  gas: the devnet end-to-end test passes with `1.05` (every relay transaction
  used 95% of its limit). Older builds under-report by about
  8-10% (measured on a pre-release v3.2.5 devnet, where `1.15` left 4-7%
  headroom); `1.15` is the safe default until you have measured your nodes.
- `dynamic_gas_price.backend = 'cosmos-evm-feemarket'` reads the chain's fee
  market base fee (floor 0.1 uqor per gas) instead of guessing.

## Keys

```bash
qorel keys add --chain qorechain-vladi --mnemonic-file ./relayer.mnemonic
qorel keys register-pqc --chain qorechain-vladi
qorel keys pqc-status --chain qorechain-vladi
```

- `keys add` (or `--key-file` with a key file that contains the mnemonic)
  stores the secp256k1 key as Hermes does and, on a hybrid chain, derives the
  ML-DSA-87 key from the same mnemonic and account with the QoreChain wallet
  derivation. Only its 32-byte seed is stored, next to the key, as
  `<key name>.pqc`, readable by the owner only. Nothing secret is printed.
- `keys register-pqc` sends `MsgRegisterPQCKeyV2` once (the only transaction
  QoreChain accepts with the classical signature alone), with a proof of
  possession on networks at v3.2.3 or later. It is idempotent and refuses to
  send when the account already has a different key.
- `keys pqc-status` shows whether the key is registered, matches the local
  key, was proven by a proof of possession, and which sign bytes the chain
  verifies. `ready_to_relay` must be `true`.
- Use a dedicated relayer account with a small balance, never a validator
  operator key.

## Safety checks

Before every transaction to a hybrid chain, QORel checks that the
post-quantum key is loaded, registered on chain and identical to the local
one, and that the sign-bytes version is known. If any check fails it sends
nothing (no fee is spent) and the health check reports the reason. A refusal
by the chain with codespace `pqc` code 21 makes it re-read the version and
the registration before the next transaction.

## IBC v1 notes for ibc-go v10 chains

- ICS-29 fee middleware no longer exists in ibc-go v10; fees are gas price,
  fee granter and the dynamic base fee.
- ibc-go v10 no longer puts the header in `update_client` events. QORel reads
  it from the `MsgUpdateClient` transaction instead, so misbehaviour
  detection keeps working (stock Hermes 1.13 disables it on these chains).

## Local devnet

`scripts/qorel-devnet/` builds a QoreChain node and an ibc-go v10 simapp node
locally and runs an end-to-end ICS-20 test in both directions; see its README.
