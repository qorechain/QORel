QORel is an IBC relayer for QoreChain and any Cosmos SDK chain, based on Hermes 1.13.3 by Informal Systems.

## Highlights

- **Post-quantum hybrid signing for QoreChain.** With `signing = "qorechain-hybrid"`, QORel adds the ML-DSA-87 (FIPS 204) signature QoreChain verifies on every transaction. Every other chain uses the standard Hermes transaction format, byte for byte.
- **Key commands:**
  - `keys add` derives the post-quantum key from the same mnemonic;
  - `keys register-pqc` registers it once, with proof of possession;
  - `keys pqc-status` checks that it is ready.
- **Pre-send check.** Before each transaction QORel confirms the post-quantum key is registered and resolves the sign-bytes version from the chain.
- **Fee market gas price** for QoreChain (`dynamic_gas_price.backend = 'cosmos-evm-feemarket'`).
- **Misbehaviour detection on ibc-go v10 chains.** QORel recovers the header from the `MsgUpdateClient` transaction; upstream Hermes 1.13 disables detection there.
- **Rate-limited endpoints.** Packet workers stay up and keep retrying while a relay or clearing attempt has failed.
- **Key files** are written owner-only (0600).

## Install

See [docs/qorel/INSTALL.md](https://github.com/qorechain/QORel/blob/main/docs/qorel/INSTALL.md).

| Format | Targets |
|---|---|
| Tarballs | Linux x86_64 / arm64 (glibc 2.28+), macOS arm64 / x86_64 |
| Packages | `.deb` and `.rpm` (amd64 / arm64) |
| Container | `ghcr.io/qorechain/qorel` |

Verify the files with `SHA256SUMS` and `gh attestation verify <file> --repo qorechain/QORel`.

## Status

- Tested on the QoreChain testnet <-> Cosmos Hub public testnet. This is a 0.x pre-release.
- IBC v2 support comes in a later release.
