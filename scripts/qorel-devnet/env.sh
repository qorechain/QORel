# Source this. Local two-chain devnet for QORel: a QoreChain node (hybrid
# post-quantum signatures required) and an ibc-go v10 simapp node (standard
# signing). Nothing here touches a public network.
#
#   QORECHAIND  path to a qorechaind binary (its dylibs next to it)
#   SIMD        path to an ibc-go v10 simapp `simd` binary
#   QOREL       path to the QORel binary (default: this repo's release build)
#   QOREL_DEVNET_DIR  where chain homes, logs and keys live
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export QOREL_DEVNET_DIR="${QOREL_DEVNET_DIR:-$HOME/.qorel-devnet}"
export QORECHAIND="${QORECHAIND:-$QOREL_DEVNET_DIR/bin/qorechaind}"
export SIMD="${SIMD:-$QOREL_DEVNET_DIR/bin/simd}"
export QOREL="${QOREL:-$REPO/target/release/qorel}"
export DYLD_LIBRARY_PATH="$(dirname "$QORECHAIND")${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="$(dirname "$QORECHAIND")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

export QC_ID=qorechain-devnet QC_HOME="$QOREL_DEVNET_DIR/qorechain"
export QC_RPC=127.0.0.1:53657 QC_P2P=127.0.0.1:53656 QC_GRPC=127.0.0.1:53090 QC_API=127.0.0.1:53317
export SIM_ID=simapp-devnet-1 SIM_HOME="$QOREL_DEVNET_DIR/simapp"
export SIM_RPC=127.0.0.1:54657 SIM_P2P=127.0.0.1:54656 SIM_GRPC=127.0.0.1:54090 SIM_API=127.0.0.1:54317
export QOREL_HOME="$QOREL_DEVNET_DIR/qorel"
export KR="--keyring-backend test"

qc()  { "$QORECHAIND" "$@"; }
sim() { "$SIMD" "$@"; }
qorel() { "$QOREL" --config "$QOREL_HOME/config.toml" "$@"; }

# height RPC: latest block height of a node (0 when down)
height() { curl -s "http://$1/status" 2>/dev/null | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["result"]["sync_info"]["latest_block_height"])
except Exception: print(0)'; }

# wait_height RPC N: wait until the node is past height N
wait_height() { for _ in $(seq 1 90); do [ "$(height "$1")" -gt "$2" ] && return 0; sleep 1; done; return 1; }

# balance BIN NODE ADDR DENOM_PREFIX: amount of the first denom starting with the prefix
balance() { "$1" q bank balances "$3" --node "tcp://$2" -o json 2>/dev/null | python3 -c '
import sys,json
p=sys.argv[1]
for c in json.load(sys.stdin).get("balances",[]):
    if c["denom"].startswith(p): print(c["amount"]); break
else: print(0)' "$4"; }
