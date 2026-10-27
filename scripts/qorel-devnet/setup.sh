#!/usr/bin/env bash
# Builds both devnet chains from scratch and starts them in the background.
set -euo pipefail
source "$(dirname "$0")/env.sh"

for p in "start --home $QC_HOME" "start --home $SIM_HOME" "$QOREL_HOME/config.toml start"; do pkill -f "$p" 2>/dev/null || true; done
sleep 1
rm -rf "$QC_HOME" "$SIM_HOME" "$QOREL_HOME"
mkdir -p "$QOREL_HOME"

# One relayer mnemonic for both chains (devnet only; never reuse it anywhere).
if [ ! -s "$QOREL_DEVNET_DIR/relayer.mnemonic" ]; then
  ( umask 077; sim keys mnemonic > "$QOREL_DEVNET_DIR/relayer.mnemonic" 2>/dev/null )
fi

# ---------- QoreChain ----------
qc init devnet --chain-id "$QC_ID" --home "$QC_HOME" >/dev/null 2>&1
qc keys add val  $KR --home "$QC_HOME" >/dev/null 2>&1
qc keys add user $KR --home "$QC_HOME" >/dev/null 2>&1
python3 - "$QC_HOME/config/genesis.json" <<'PY'
import json,sys
p=sys.argv[1]; g=json.load(open(p)); a=g["app_state"]
# Same post-quantum rules as mainnet: hybrid signature required, no classical fallback.
a["pqc"]["params"].update({"hybrid_signature_mode":2,"allow_classical_fallback":False})
# Same IBC policy as mainnet.
a["ibc"]["client_genesis"]["params"]["allowed_clients"]=["07-tendermint"]
a["gov"]["params"].update({"voting_period":"20s","expedited_voting_period":"10s"})
json.dump(g,open(p,"w"))
PY
qc genesis add-genesis-account "$(qc keys show val -a $KR --home "$QC_HOME")" 10000000000000uqor --home "$QC_HOME"
qc genesis add-genesis-account "$(qc keys show user -a $KR --home "$QC_HOME")" 1000000000000uqor --home "$QC_HOME"
qc genesis gentx val 300000000000uqor --chain-id "$QC_ID" $KR --home "$QC_HOME" >/dev/null 2>&1
qc genesis collect-gentxs --home "$QC_HOME" >/dev/null 2>&1
sed -i.bak 's/^timeout_commit *=.*/timeout_commit = "1s"/; s|^pprof_laddr *=.*|pprof_laddr = ""|' "$QC_HOME/config/config.toml"
python3 - "$QC_HOME/config/app.toml" "$QC_GRPC" "$QC_API" <<'PY'
import sys
p,grpc,api=sys.argv[1:]; sec=None; out=[]
want={"[api]":{"enable":"true","address":f'"tcp://{api}"'},"[grpc]":{"enable":"true","address":f'"{grpc}"'},
      "[json-rpc]":{"enable":"false"},"[grpc-web]":{"enable":"false"}}
for line in open(p):
    t=line.strip()
    if t.startswith("[") and t.endswith("]"): sec=t
    k=t.split("=")[0].strip() if "=" in t else ""
    if sec in want and k in want[sec]: line=f"{k} = {want[sec][k]}\n"
    if k=="minimum-gas-prices" and sec is None: line='minimum-gas-prices = "0uqor"\n'
    out.append(line)
open(p,"w").writelines(out)
PY

# ---------- simapp (ibc-go v10) ----------
sim init devnet --chain-id "$SIM_ID" --home "$SIM_HOME" >/dev/null 2>&1
sim keys add val  $KR --home "$SIM_HOME" >/dev/null 2>&1
sim keys add user $KR --home "$SIM_HOME" >/dev/null 2>&1
sim genesis add-genesis-account "$(sim keys show val -a $KR --home "$SIM_HOME")" 10000000000000stake --home "$SIM_HOME"
sim genesis add-genesis-account "$(sim keys show user -a $KR --home "$SIM_HOME")" 1000000000000stake --home "$SIM_HOME"
sim genesis gentx val 300000000000stake --chain-id "$SIM_ID" $KR --home "$SIM_HOME" >/dev/null 2>&1
sim genesis collect-gentxs --home "$SIM_HOME" >/dev/null 2>&1
sed -i.bak 's/^timeout_commit *=.*/timeout_commit = "1s"/; s|^pprof_laddr *=.*|pprof_laddr = ""|' "$SIM_HOME/config/config.toml"
sed -i.bak 's/^minimum-gas-prices *=.*/minimum-gas-prices = "0stake"/' "$SIM_HOME/config/app.toml"
python3 - "$SIM_HOME/config/app.toml" "$SIM_GRPC" "$SIM_API" <<'PY'
import sys
p,grpc,api=sys.argv[1:]; sec=None; out=[]
want={"[api]":{"enable":"true","address":f'"tcp://{api}"'},"[grpc]":{"enable":"true","address":f'"{grpc}"'}}
for line in open(p):
    t=line.strip()
    if t.startswith("[") and t.endswith("]"): sec=t
    k=t.split("=")[0].strip() if "=" in t else ""
    if sec in want and k in want[sec]: line=f"{k} = {want[sec][k]}\n"
    out.append(line)
open(p,"w").writelines(out)
PY

# ---------- QORel config and keys ----------
sed -e "s|@QC_RPC@|$QC_RPC|g; s|@QC_GRPC@|$QC_GRPC|g; s|@SIM_RPC@|$SIM_RPC|g; s|@SIM_GRPC@|$SIM_GRPC|g; s|@KEYS@|$QOREL_HOME/keys|g" \
  "$(dirname "$0")/config.toml.in" > "$QOREL_HOME/config.toml"
qorel keys add --chain "$QC_ID"  --mnemonic-file "$QOREL_DEVNET_DIR/relayer.mnemonic" >/dev/null
qorel keys add --chain "$SIM_ID" --mnemonic-file "$QOREL_DEVNET_DIR/relayer.mnemonic" >/dev/null
RQ=$(qorel --json keys list --chain "$QC_ID"  | tail -1 | python3 -c 'import sys,json;print(list(json.load(sys.stdin)["result"].values())[0]["account"])')
RS=$(qorel --json keys list --chain "$SIM_ID" | tail -1 | python3 -c 'import sys,json;print(list(json.load(sys.stdin)["result"].values())[0]["account"])')
qc  genesis add-genesis-account "$RQ" 100000000000uqor  --home "$QC_HOME"
sim genesis add-genesis-account "$RS" 100000000000stake --home "$SIM_HOME"
echo "relayer: $RQ / $RS"

nohup "$QORECHAIND" start --home "$QC_HOME" --rpc.laddr "tcp://$QC_RPC" --p2p.laddr "tcp://$QC_P2P" \
  > "$QOREL_DEVNET_DIR/qorechain.log" 2>&1 &
nohup "$SIMD" start --home "$SIM_HOME" --rpc.laddr "tcp://$SIM_RPC" --p2p.laddr "tcp://$SIM_P2P" \
  > "$QOREL_DEVNET_DIR/simapp.log" 2>&1 &
wait_height "$QC_RPC" 2 && wait_height "$SIM_RPC" 2
echo "chains up: $QC_ID h=$(height "$QC_RPC"), $SIM_ID h=$(height "$SIM_RPC")"
