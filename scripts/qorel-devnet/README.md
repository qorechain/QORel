# QORel local devnet

Two local chains and QORel between them, to test hybrid signing end to end:

- **qorechain-devnet**: a QoreChain node configured like mainnet (hybrid
  post-quantum signature required on every transaction, only `07-tendermint`
  clients allowed);
- **simapp-devnet-1**: the ibc-go v10 simapp, signing the standard way.

Requirements: a `qorechaind` binary with its libraries next to it, an ibc-go
v10 `simd`, and QORel built with `cargo build --release -p ibc-relayer-cli`.
Paths are set in `env.sh` (`QORECHAIND`, `SIMD`, `QOREL`); everything lives in
`$QOREL_DEVNET_DIR` (default `~/.qorel-devnet`).

```bash
bash scripts/qorel-devnet/setup.sh   # fresh chains + QORel config and keys
bash scripts/qorel-devnet/e2e.sh     # register keys, open a channel, relay ICS-20 both ways
```

`e2e.sh` checks: post-quantum key registration (idempotent), client,
connection and channel creation, transfers in both directions, unwinding a
voucher, a timed-out packet cleared and refunded on QoreChain, a transfer sent
by QORel itself, clean relayer logs with misbehaviour checks running, and that
every transaction QORel sent to QoreChain succeeded.

The relayer mnemonic in `$QOREL_DEVNET_DIR/relayer.mnemonic` is for this local
devnet only.
