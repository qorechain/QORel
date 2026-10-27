#!/usr/bin/env bash
# End-to-end ICS-20 test on the devnet built by setup.sh:
#   QoreChain (hybrid signatures required) <-> ibc-go v10 simapp (standard).
# Every transaction QORel sends to QoreChain carries the hybrid signature.
set -euo pipefail
source "$(dirname "$0")/env.sh"

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; exit 1; }
# wait_change CMD OLD: wait until CMD prints something other than OLD
wait_change() { local v; for _ in $(seq 1 60); do v=$(eval "$1"); [ "$v" != "$2" ] && { echo "$v"; return 0; }; sleep 2; done; echo "$2"; return 1; }
start_relayer() { nohup "$QOREL" --config "$QOREL_HOME/config.toml" start > "$QOREL_DEVNET_DIR/qorel-$1.log" 2>&1 & disown; sleep 8; }
stop_relayer() { pkill -f "$QOREL_HOME/config.toml start" 2>/dev/null || true; sleep 2; }
trap stop_relayer EXIT
stop_relayer
# qc_hybrid TX...: a QoreChain user transaction, hybrid-signed with the qorechaind CLI
qc_hybrid() { local t; t=$(mktemp)
  qc tx "$@" --from user $KR --home "$QC_HOME" --chain-id "$QC_ID" --node "tcp://$QC_RPC" --fees 200000uqor --gas 600000 --generate-only > "$t" 2>/dev/null
  qc tx pqc cosign "$t" --from user --pqc-key user-pqc $KR --home "$QC_HOME" --chain-id "$QC_ID" --node "tcp://$QC_RPC" -y -b sync -o json 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(d.get("code",0))'
  rm -f "$t"; }

SU=$(sim keys show user -a $KR --home "$SIM_HOME")
QU=$(qc keys show user -a $KR --home "$QC_HOME")
RS=$(qorel --json keys list --chain "$SIM_ID" 2>/dev/null | tail -1 | python3 -c 'import sys,json;print(list(json.load(sys.stdin)["result"].values())[0]["account"])')

# 1. Post-quantum keys: the relayer's (via QORel) and the QoreChain test user's.
qorel --json keys register-pqc --chain "$QC_ID" 2>/dev/null | tail -1 | grep -q '"status":"success"' || fail "register-pqc"
qorel --json keys pqc-status --chain "$QC_ID" 2>/dev/null | tail -1 | grep -q '"ready_to_relay":true' || fail "pqc-status"
qorel --json keys register-pqc --chain "$QC_ID" 2>/dev/null | tail -1 | grep -q '"already_registered":true' || fail "register-pqc idempotent"
pass "relayer post-quantum key registered (idempotent)"
PUB=$(qc tx pqc gen-key user-pqc $KR --home "$QC_HOME" 2>&1 | sed -n 's/^public_key_hex: //p')
qc tx pqc register-key-v2 dilithium5 "$PUB" hybrid --from user --pqc-key user-pqc $KR --home "$QC_HOME" --chain-id "$QC_ID" \
  --node "tcp://$QC_RPC" --fees 2000000uqor --gas 600000 -y -b sync -o json >/dev/null 2>&1
sleep 4

# 2. Clients, connection and channel (QoreChain side hybrid-signed by QORel).
qorel create channel --a-chain "$QC_ID" --b-chain "$SIM_ID" --a-port transfer --b-port transfer \
  --new-client-connection --yes > "$QOREL_DEVNET_DIR/create-channel.log" 2>&1 || fail "create channel"
pass "clients, connection-0 and channel-0 created"

start_relayer 1

# 3. QoreChain -> simapp
qc_hybrid ibc-transfer transfer transfer channel-0 "$SU" 1000000uqor || fail "send uqor"
v=$(wait_change "balance $SIMD $SIM_RPC $SU ibc/" 0) && [ "$v" = 1000000 ] || fail "uqor did not arrive on simapp ($v)"
pass "QoreChain -> simapp: 1000000uqor received as voucher"

# 4. simapp -> QoreChain (MsgRecvPacket on QoreChain)
sim tx ibc-transfer transfer transfer channel-0 "$QU" 777000stake --from user $KR --home "$SIM_HOME" --chain-id "$SIM_ID" \
  --node "tcp://$SIM_RPC" --fees 1000stake -y -b sync -o json >/dev/null 2>&1
v=$(wait_change "balance $QORECHAIND $QC_RPC $QU ibc/" 0) && [ "$v" = 777000 ] || fail "stake did not arrive on QoreChain ($v)"
pass "simapp -> QoreChain: 777000stake received as voucher"

# 5. Unwind the uqor voucher back to QoreChain
D=$(sim q bank balances "$SU" --node "tcp://$SIM_RPC" -o json | python3 -c 'import sys,json;print([c["denom"] for c in json.load(sys.stdin)["balances"] if c["denom"].startswith("ibc/")][0])')
b0=$(balance "$QORECHAIND" "$QC_RPC" "$QU" uqor)
sim tx ibc-transfer transfer transfer channel-0 "$QU" "400000$D" --from user $KR --home "$SIM_HOME" --chain-id "$SIM_ID" \
  --node "tcp://$SIM_RPC" --fees 1000stake -y -b sync -o json >/dev/null 2>&1
b1=$(wait_change "balance $QORECHAIND $QC_RPC $QU uqor" "$b0") && [ $((b1-b0)) = 400000 ] || fail "unwind ($b0 -> $b1)"
pass "voucher unwound: +400000uqor back on QoreChain"

# 6. Timeout: QoreChain packet expires while the relayer is down; QORel times it out on QoreChain.
stop_relayer
b0=$(balance "$QORECHAIND" "$QC_RPC" "$QU" uqor)
qc_hybrid ibc-transfer transfer transfer channel-0 "$SU" 5000000uqor --packet-timeout-timestamp 10000000000 --packet-timeout-height 0-0 || fail "send timeout packet"
sleep 6; b1=$(balance "$QORECHAIND" "$QC_RPC" "$QU" uqor); sleep 14
start_relayer 2
b2=$(wait_change "balance $QORECHAIND $QC_RPC $QU uqor" "$b1") && [ $((b2-b1)) = 5000000 ] || fail "timeout refund ($b1 -> $b2)"
pass "timed-out packet cleared and refunded on QoreChain (MsgTimeout)"

# 7. A transfer sent by QORel itself from QoreChain (MsgTransfer hybrid-signed by QORel).
r0=$(balance "$SIMD" "$SIM_RPC" "$RS" ibc/)
qorel tx ft-transfer --dst-chain "$SIM_ID" --src-chain "$QC_ID" --src-port transfer --src-channel channel-0 \
  --amount 123456 --denom uqor --timeout-seconds 600 > /dev/null 2>&1 || fail "ft-transfer"
r1=$(wait_change "balance $SIMD $SIM_RPC $RS ibc/" "$r0") && [ $((r1-r0)) = 123456 ] || fail "ft-transfer arrival ($r0 -> $r1)"
pass "QORel ft-transfer from QoreChain delivered"

sleep 10
# An ERROR right before Hermes' own "account sequence mismatch ... retrying"
# recovery (normal after a restart) is not a failure.
errors=$(python3 - "$QOREL_DEVNET_DIR"/qorel-1.log "$QOREL_DEVNET_DIR"/qorel-2.log <<'PY2'
import sys
n=0
for f in sys.argv[1:]:
    lines=open(f).read().splitlines()
    for i,l in enumerate(lines):
        if " ERROR " in l and not (i+1<len(lines) and "mismatched account sequence number" in lines[i+1]):
            n+=1; print(l[:300], file=sys.stderr)
print(n)
PY2
)
[ "$errors" = 0 ] || fail "$errors errors in the relayer logs"
grep -q "No evidence of misbehavior detected for chain $QC_ID" "$QOREL_DEVNET_DIR"/qorel-*.log || fail "misbehaviour checks did not run"
pass "relayer logs clean; misbehaviour checks ran on both chains"

# 8. Every QoreChain transaction QORel sent succeeded.
R=$(qorel --json keys list --chain "$QC_ID" 2>/dev/null | tail -1 | python3 -c 'import sys,json;print(list(json.load(sys.stdin)["result"].values())[0]["account"])')
curl -s "http://$QC_RPC/tx_search?query=%22message.sender=%27$R%27%22&per_page=100" | python3 -c '
import sys,json
txs=json.load(sys.stdin)["result"]["txs"]
bad=[t for t in txs if t["tx_result"]["code"]!=0]
print(f"PASS {len(txs)} QoreChain transactions from the relayer, {len(bad)} failed")
for t in txs:
    r=t["tx_result"]; u=int(r["gas_used"]); w=int(r["gas_wanted"])
    h=t["height"]; size=len(t["tx"])*3//4
    print(f"     h={h:>5} gas {u:>7}/{w:<7} ({w/u:.2f}x) ~{size} B")
sys.exit(1 if bad else 0)' || fail "a relayer transaction failed on QoreChain"
stop_relayer
echo "ALL PASSED"
