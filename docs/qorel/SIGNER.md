# QORel signer layer

## Why

QORel relays between any Cosmos SDK chains. Most chains verify one classical
signature per transaction; some require more. QoreChain refuses any
transaction without an additional ML-DSA-87 (FIPS 204) signature, so a stock
relayer cannot submit to it. QORel keeps the standard path untouched and adds
a co-signer step for chains that need one.

## Where it runs

The relayer builds a transaction in this order:

1. encode the `TxBody` with the messages and memo, without any co-signer
   extension: `B0`;
2. encode the final `AuthInfo` (signer public key, `SIGN_MODE_DIRECT`,
   sequence, fee, gas limit): `A`;
3. **co-signer**: `extension_options(chain_id, B0, A)` returns the extension
   options to append;
4. re-encode the body with those options and make the classical signature
   over `SignDoc(final body, A, chain id, account number)`.

Gas simulation and batch-size estimation go through the same path, so the
extra bytes and verification gas are always accounted for.

## Interfaces

- `PqSigner`: a post-quantum primitive (`algorithm_id`, `public_key`, `sign`).
  `MlDsa87Signer` is provided (hedged signing by default, deterministic for
  test vectors; every signature is verified before use).
- `SignBytesFramer`: a chain's rules: `check_body`, `frame`, `pack`.
- `TxExtensionSigner`: what the relayer calls. `PqExtensionSigner` combines a
  primitive and a framer.

A new post-quantum chain implements a framer (and a primitive if it uses
another algorithm); nothing else in the relayer changes.

## QoreChain hybrid contract

- Message signed by ML-DSA-87, v2:
  `"qorechain-pqc-hybrid-v2" || BE64(len chainID) || chainID || BE32(len B0) || B0 || BE32(len A) || A`.
  v1 omits the domain tag and chain id.
- `qorechain-vladi` and `qorechain-diana` verify v1 until the `v3.2.0` (or
  testnet `v3.1.98`) upgrade is applied and v2 after; both have applied it.
  The relayer reads `cosmos.upgrade.v1beta1` applied plans into a
  `VersionCell`; until then it refuses to sign for those chains. Other chain
  ids verify v2 from genesis.
- The signature travels as `/qorechain.pqc.v1.PQCHybridSignature
  {algorithm_id = 1, pqc_signature (4627 bytes), pqc_public_key (optional)}`,
  the only critical extension option of the transaction.
- `B0` must be canonical, because the chain re-derives it by decoding the
  body, dropping the hybrid option and re-encoding. The framer refuses bodies
  with their own extension options, the `unordered` flag, unknown fields or a
  non-canonical encoding.
- A refusal with codespace `pqc` code 21 means the hybrid signature did not
  verify; the relayer re-reads the version once before retrying.
- Gas: 2000 gas per keyed signer for the verification (charged in simulation
  too) plus the size cost of about 4.7 KB of extension.

## Keys

The ML-DSA-87 key is derived from the relayer's mnemonic and account with the
QoreChain wallet derivation:
`seed = SHAKE256("qorechain:pqc:v1|" + qor1-address + "|" + mnemonic)[..32]`,
then FIPS 204 `KeyGen_internal(seed)`. The account registers the public key
once with `MsgRegisterPQCKeyV2` before relaying. Secrets are zeroized and never
printed.
