#!/usr/bin/env bash
# Isolated GitHub-hosted D148 proof. Never run on an owner's device/host.
# Receiver and sender are independent processes/network namespaces.
# Sender uses the real Rust sender engine + CI synthetic owner action, NOT Android ART.
set -euo pipefail
if [[ "$GITHUB_ACTIONS" != true || "$RUNNER_OS" != Linux ||
      "$D148_HOSTED_CI_ONLY" != isolated || -z "$RUNNER_TEMP" ]]; then
  echo 'D148 netns fixture refuses non-GitHub environments' >&2; exit 1
fi
test "$(id -u)" -ne 0
test -s "$D148_TEST_BINARY"
uid="$(id -u)"
gid="$(id -g)"
test -x "$(command -v setpriv)"
base="$(mktemp -d "$RUNNER_TEMP/opendrop-d148.XXXXXXXX")"
chmod 700 "$base"
na=od148rx
nb=od148tx
ia=od148a
ib=od148b
ip_a=10.251.42.11
ip_b=10.251.42.12
rx_pid=""
tx_pid=""
clean() {
  if [[ -n "$tx_pid" ]]; then kill "$tx_pid" 2>/dev/null || true; wait "$tx_pid" 2>/dev/null || true; tx_pid=""; fi
  if [[ -n "$rx_pid" ]]; then kill "$rx_pid" 2>/dev/null || true; wait "$rx_pid" 2>/dev/null || true; rx_pid=""; fi
  sudo ip netns delete "$na" 2>/dev/null || true
  sudo ip netns delete "$nb" 2>/dev/null || true
}
on_exit() {
  local code=$?
  if [[ "$code" -ne 0 ]]; then
    for f in "$base"/*-rx.log "$base"/*-tx.log; do
      if [[ -f "$f" ]]; then
        echo "D148_SCOPED_FAILURE_LOG=$f" >&2
        tail -n 85 "$f" >&2
      fi
    done
  fi
  clean
}
trap on_exit EXIT
setup() {
  clean
  sudo ip netns add "$na"
  sudo ip netns add "$nb"
  sudo ip link add "$ia" type veth peer name "$ib"
  sudo ip link set "$ia" netns "$na"
  sudo ip link set "$ib" netns "$nb"
  sudo ip -n "$na" addr add "$ip_a/24" dev "$ia"
  sudo ip -n "$nb" addr add "$ip_b/24" dev "$ib"
  sudo ip -n "$na" link set lo up
  sudo ip -n "$nb" link set lo up
  sudo ip -n "$na" link set "$ia" up
  sudo ip -n "$nb" link set "$ib" up
  # Absolutely no route to public internet exists in either namespace.
  test -z "$(sudo ip -n "$na" route show default)"
  test -z "$(sudo ip -n "$nb" route show default)"
}
receiver() {
  local scenario="$1" root="$2" out="$3"
  timeout --kill-after=3s 40s sudo ip netns exec "$na" setpriv --reuid="$uid" --regid="$gid" --clear-groups env D148_FIXTURE_CI=isolate-only D148_SCENARIO="$scenario" D148_INTERFACE="$ia" D148_LOCAL_IPV4="$ip_a" D148_LOCAL_PREFIX=24 D148_RECEIVER_ROOT="$root" "$D148_TEST_BINARY" --exact runtime::d148_netns_fixture::hosted_receiver_process_real_udp_tcp_tls_file --ignored --nocapture --test-threads=1 >"$out" 2>&1 &
  rx_pid=$!
}
sender() {
  local scenario="$1" out="$2"
  timeout --kill-after=3s 40s sudo ip netns exec "$nb" setpriv --reuid="$uid" --regid="$gid" --clear-groups env D148_FIXTURE_CI=isolate-only D148_SCENARIO="$scenario" D148_INTERFACE="$ib" D148_LOCAL_IPV4="$ip_b" D148_LOCAL_PREFIX=24 "$D148_TEST_BINARY" --exact runtime::d148_netns_fixture::hosted_sender_process_real_udp_tcp_tls_file --ignored --nocapture --test-threads=1 >"$out" 2>&1 &
  tx_pid=$!
}
positive_assert() {
  local root="$1" rx="$2" tx="$3"
  grep -q D148_TCP_SELECTED_FROM_REAL_DISCOVERY "$rx"
  if ! grep -q D148_REAL_UDP_DISCOVERY_RX "$tx"; then
    grep -q D148_HOTSPOT_ACCEPTED_PEER "$tx"
  fi
  grep -q D148_OWNER_EXACT_OFFER=ACCEPT_SIMULATED "$rx"
  grep -q D148_SENDER_AUTHENTICATED_COMPLETE "$tx"
  grep -q D148_RECEIVER_COMMITTED "$rx"
  local code1 code2
  # The real ten-digit SAS is rendered as 5 digits, a hyphen, then 5
  # digits; do NOT change production UI to satisfy a test-log parser.
  code1="$(grep -oE 'D148_RECEIVER_SAS=[0-9]{5}-[0-9]{5}' "$rx" | tail -1 | cut -d= -f2)"
  code2="$(grep -oE 'D148_SENDER_SAS=[0-9]{5}-[0-9]{5}' "$tx" | tail -1 | cut -d= -f2)"
  test -n "$code1" && test "$code1" = "$code2"
  python3 - "$root/destination/d148-synthetic.bin" "$root/private/journal.sqlite" "$tx" "$rx" <<'PY'
import hashlib,sqlite3,sys
path,journal,tx,rx=sys.argv[1:]
expected=bytes(n%251 for n in range(131123))
with open(path,'rb') as f: actual=f.read()
assert actual==expected, 'independent published file mismatch'
sha=hashlib.sha256(expected).hexdigest()
with sqlite3.connect(f'file:{journal}?mode=ro',uri=True) as con:
 rows=con.execute('SELECT phase,bytes,sha FROM transfers').fetchall()
assert rows==[('committed',len(expected),sha)],rows
assert f'D148_SENDER_AUTHENTICATED_COMPLETE sha256={sha}' in open(tx).read()
assert f'D148_RECEIVER_COMMITTED sha256={sha}' in open(rx).read()
print(f'D148_INDEPENDENT_PUBLISHED_SHA256={sha} bytes={len(expected)} journal_exactly_one_committed=true')
PY
}
run_case() {
  local scenario="$1"
  setup
  local root="$base/$scenario" rxlog="$base/$scenario-rx.log" txlog="$base/$scenario-tx.log"
  mkdir -p "$root"
  chmod 700 "$root"
  receiver "$scenario" "$root" "$rxlog"
  sleep 0.5
  if [[ "$scenario" == interface_loss ]]; then
    sudo ip -n "$na" link set "$ia" down
  elif [[ "$scenario" != blocked && "$scenario" != cancel ]]; then
    if [[ "$scenario" == normal ]]; then
      # Real UDP spoofed candidates cross from the peer namespace.
      sudo ip netns exec "$nb" setpriv --reuid="$uid" --regid="$gid" --clear-groups python3 - <<PY
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
s.bind(("$ip_b",0))
for bad in (b'ODNB'+bytes([1,99,0xab,0xd7])+b'Z'*16,
            b'ODNB'+bytes([1,2,0xab,0xd6])+b'X'*16,
            b'ODNB'+bytes([1,2,0xab,0xd7])+bytes(16)):
 s.sendto(bad, ("10.251.42.255",43992))
print('D148_SPOOFED_CANDIDATES_UDP_SENT=3')
PY
    fi
    sender "$scenario" "$txlog"
  fi
  local code=0
  wait "$rx_pid" || code=$?
  rx_pid=""
  if [[ -n "$tx_pid" ]]; then wait "$tx_pid" || code=$?; tx_pid=""; fi
  cat "$rxlog"
  if [[ -f "$txlog" ]]; then cat "$txlog"; fi
  test "$code" -eq 0
  if [[ "$scenario" == normal || "$scenario" == hotspot ]]; then
    positive_assert "$root" "$rxlog" "$txlog"
    echo "D148_E2E_PASS=$scenario UDP->TCP->strict RPK TLS->SAS->Offer->SHA->Commit->Complete"
  else
    grep -Fq "D148_NEGATIVE_RECEIVER_FAIL_CLOSED=$scenario" "$rxlog"
    if [[ "$scenario" == no_listener ]]; then grep -q D148_NO_LISTENER_BEACON_SENT "$txlog"; fi
    if [[ "$scenario" == sas_decline || "$scenario" == decline || "$scenario" == collision ]]; then
      grep -Fq "D148_SENDER_REJECTED=$scenario" "$txlog"
    fi
    if [[ "$scenario" != collision ]]; then
      test ! -e "$root/destination/d148-synthetic.bin"
    fi
    echo "D148_NEGATIVE_PASS=$scenario destination_not_unauthorized"
  fi
  clean
}
for scenario in normal hotspot sas_decline decline collision no_listener blocked interface_loss cancel; do
  run_case "$scenario"
done
echo 'D148_NETNS_FIXTURE_PASS=9 isolated network scenarios; real UDP selected both physical TCP directions'
