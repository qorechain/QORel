# qorel-signer

Pluggable transaction co-signers for [QORel](https://github.com/qorechain/QORel).

A co-signer adds extension options to a Cosmos SDK `TxBody` after the fee,
gas limit and sequence are final and before the classical signature is made.
Chains with standard signing use no co-signer and their transactions are
unchanged. QoreChain uses the hybrid co-signer, which adds the ML-DSA-87
(FIPS 204) signature QoreChain requires on every transaction.

The crate works on raw protobuf bytes (prost 0.13, `fips204`, `sha3`, `bech32`,
`zeroize`) and depends on no IBC or relayer types.

```rust
use qorel_signer::{SignRequest, TxExtensionSigner};
use qorel_signer::mldsa87::PqSignMode;
use qorel_signer::qorechain::{qorechain_hybrid_signer, SignBytesVersion, VersionCell};

let version = VersionCell::new();
version.set(SignBytesVersion::V2); // read from the chain's upgrade record
let signer = qorechain_hybrid_signer("qorechain-diana", &seed, PqSignMode::Hedged, version, false);
let extensions = signer.extension_options(&SignRequest {
    chain_id: "qorechain-diana",
    body_without_ext: &b0,
    auth_info: &auth_info,
    account_number,
    sequence,
})?;
```

Tests reproduce, byte for byte, relay transactions that the QoreChain v3.2.5
chain code decoded and accepted (`tests/vectors/relay-signbytes-v3.2.5.json`)
and the public `qorechain-pqc` sign-bytes vectors. See
[`docs/qorel/SIGNER.md`](../../docs/qorel/SIGNER.md) for the full contract.
