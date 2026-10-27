# Signing QoreChain transactions from any language

QORel signs in Rust with the `qorel-signer` crate. Other relayers, bots and tools can produce the same hybrid post-quantum signature in other languages with the QoreChain SDK and PQC libraries. All of them follow one contract and check against the same test vectors.

## The contract

QoreChain accepts a transaction only if it carries both signatures:

- **The classical secp256k1 signature**, in the usual `SIGN_MODE_DIRECT` form. It covers the final body, extension included.
- **An ML-DSA-87 (FIPS 204) signature** in a non-critical extension option of type `/qorechain.pqc.v1.PQCHybridSignature`: `{algorithm_id = 1, pqc_signature, pqc_public_key (optional)}`. It must be the only critical extension option.

The ML-DSA signature covers the sign bytes (version 2, current on all networks):

```
"qorechain-pqc-hybrid-v2" || BE64(len(chain_id)) || chain_id
                          || BE32(len(B0)) || B0
                          || BE32(len(A))  || A
```

- `B0` is the `TxBody` without the PQC extension, re-encoded canonically.
- `A` is the `AuthInfo` bytes, unchanged.

Order of operations:
1. Build the body and the auth info.
2. Sign the sign bytes with ML-DSA-87.
3. Append the extension to the body.
4. Sign the final body with secp256k1.
5. Broadcast.

**Registering the key.** The account registers its ML-DSA public key once with `MsgRegisterPQCKeyV2`, including a proof of possession. This is the one transaction QoreChain accepts with the classical signature alone.

**Deriving the key.** The ML-DSA key is derived from the same mnemonic as the account, with the QoreChain wallet derivation:

```
seed = SHAKE256("qorechain:pqc:v1|" + address + "|" + mnemonic)[:32]
```

Then `ML-DSA-87.KeyGen_internal(seed)`. Any wallet or relayer that imports the mnemonic gets the same post-quantum key.

Full details: [SIGNER.md](SIGNER.md).

## Libraries

| Language | Package | Hybrid signing |
|---|---|---|
| Rust | `qorel-signer` (crates.io), or `qorechain-sdk` | `qorel_signer::qorechain::qorechain_hybrid_signer` + `PqExtensionSigner`; `qorechain::tx::build_hybrid_tx` |
| TypeScript / JavaScript | `npm install @qorechain/sdk` | `TxClient` signs hybrid with a `pqcKeypair`; `ensurePqcRegistered` |
| Go | `go get github.com/qorechain/qorechain-sdk/packages/go@latest` | `qorechain/tx` (hybrid build / sign), `qorechain/signbytes`, `qorechain/pqcdx` |
| Python | `pip install qorechain-sdk` | `build_hybrid_tx`, `build_hybrid_signature_extension` |
| Java / Kotlin | `io.github.qorechain:qorechain-sdk` (Maven Central) | `PqcDx` (registration, hybrid send path) and the hybrid transaction builder |
| C and others | [`qorechain-pqc`](https://github.com/qorechain/qorechain-pqc) | ML-DSA-87 keygen / sign / verify bindings; frame the sign bytes as above |

## Test vectors

`crates/qorel-signer/tests/vectors/` holds:

- a sign-bytes known-answer file;
- relay-transaction vectors: body without the extension, sign bytes, extension bytes and the full signed transaction, rebuilt byte for byte from transactions the chain accepted;
- the cross-SDK key-derivation vector.

Run them in your language before sending anything to a live network.

## Adding post-quantum signing to another relayer

The hook point is "after the auth info is final and before the classical sign doc is built". Plug the extension in at that point:
- In Hermes-based relayers, that is `crates/relayer/src/chain/cosmos/encode.rs::sign_tx`. QORel's change there is generic: any `TxExtensionSigner` can add extension options.
- In Go relayers built on the Cosmos SDK `client/tx` package, wrap the `TxBuilder` before `SetSignatures`.
