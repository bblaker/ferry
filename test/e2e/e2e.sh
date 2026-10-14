#!/usr/bin/env bash
# End-to-end test: run the real ferry binary against a veth pair and check,
# through /metrics, that it steers, reloads, and detaches as documented.
#
#   client netns                      host (ferry attached here)
#   ferry-e2e1 10.99.0.2  <-- veth --> ferry-e2e0 10.99.0.1
#
# The client has a static neighbor entry for the VIP pointing at ferry-e2e0,
# so packets to the VIP arrive there without anyone answering ARP. Ferry is
# in shadow mode (XDP_PASS), so the kernel then drops them as not-for-us;
# only the counters show what Ferry decided.
#
# Needs root on Linux, plus iproute2, curl and ping. On macOS, `make e2e`
# runs this inside the privileged builder container. Set FERRY_BIN to test a
# prebuilt binary (`make e2e-native` does, so sudo never runs go); otherwise
# it builds one, which needs the generated BPF code.
set -euo pipefail

cd "$(dirname "$0")/../.."

MODES=${FERRY_E2E_MODES:-xdp-generic xdp-native}
NS=ferry-e2e
IF=ferry-e2e0
PEER=ferry-e2e1
VIP=192.168.1.240
METRICS=127.0.0.1:19469
WORK=$(mktemp -d)
PID=

log() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	if [[ -f $WORK/ferry.log ]]; then
		printf '\n-- ferry log --\n' >&2
		cat "$WORK/ferry.log" >&2
	fi
	exit 1
}

cleanup() {
	[[ -n $PID ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$IF" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

[[ $(id -u) == 0 ]] || fail "run as root (or use make e2e)"

# metric NAME [LABELS] prints a sample's value, or 0 if absent.
metric() {
	local want=$1
	[[ -n ${2:-} ]] && want="$1{$2}"
	curl -fsS "http://$METRICS/metrics" |
		awk -v want="$want" '$1 == want { print $2; found = 1 } END { if (!found) print 0 }'
}

# expect DESC ACTUAL OP EXPECTED, where OP is a test(1) integer operator.
expect() {
	if [ "$2" "$3" "$4" ]; then
		printf 'ok   %s (%s)\n' "$1" "$2"
	else
		fail "$1: got $2, want $3 $4"
	fi
}

wait_for() {
	local i
	for i in $(seq 50); do
		if eval "$1" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
	done
	fail "timed out waiting for: $1"
}

# udp_flows N sends one datagram from each of N fresh sockets, so each is a
# new flow with its own source port.
udp_flows() {
	ip netns exec "$NS" bash -c "for i in \$(seq $1); do echo x > /dev/udp/$VIP/53; done"
}

# tcp_flows N starts N connections to the VIP; each sends a SYN and gives up.
tcp_flows() {
	ip netns exec "$NS" bash -c "for i in \$(seq $1); do timeout 0.2 bash -c 'echo > /dev/tcp/$VIP/443' 2>/dev/null & done; wait" || true
}

start_ferry() {
	"$FERRY_BIN" attach -iface "$IF" -mode "$1" -config "$WORK/ferry.json" -metrics-addr "$METRICS" \
		>>"$WORK/ferry.log" 2>&1 &
	PID=$!
	wait_for "curl -fsS http://$METRICS/healthz"
}

if [[ -z ${FERRY_BIN:-} ]]; then
	log "build"
	go build -o "$WORK/ferry-bin" ./cmd/ferry
	FERRY_BIN=$WORK/ferry-bin
fi
"$FERRY_BIN" version
"$FERRY_BIN" check -config test/e2e/ferry.json

log "topology"
ip netns add "$NS"
ip link add "$IF" type veth peer name "$PEER" netns "$NS"
ip addr add 10.99.0.1/24 dev "$IF"
ip link set "$IF" up
ip -n "$NS" addr add 10.99.0.2/24 dev "$PEER"
ip -n "$NS" link set "$PEER" up
ip -n "$NS" link set lo up
ip -n "$NS" route add "$VIP/32" dev "$PEER"
ip -n "$NS" neigh add "$VIP" lladdr "$(cat /sys/class/net/$IF/address)" dev "$PEER"

for mode in $MODES; do
	log "$mode: attach"
	cp test/e2e/ferry.json "$WORK/ferry.json"
	: >"$WORK/ferry.log"
	start_ferry "$mode"
	ip link show dev "$IF" | grep -q 'prog/xdp' || fail "no XDP program on $IF"
	expect "services programmed" "$(metric ferry_services)" -eq 2
	expect "backends active" "$(metric ferry_backends)" -eq 5

	log "$mode: non-VIP traffic is untouched"
	ip netns exec "$NS" ping -c 3 -i 0.2 -W 1 10.99.0.1 >/dev/null || fail "ping through shadow-mode ferry failed"
	expect "ping not counted as a service hit" "$(metric ferry_service_hits_total)" -eq 0

	log "$mode: VIP traffic is steered"
	udp_flows 100
	tcp_flows 40
	hits=$(metric ferry_service_hits_total)
	expect "service hits" "$hits" -ge 140
	sum=0
	for b in 10.42.0.20:53 10.42.1.21:53 10.42.0.11:8443 10.42.1.12:8443 10.42.2.13:8443; do
		n=$(metric ferry_backend_packets_total "backend=\"$b\"")
		expect "packets to $b" "$n" -gt 0
		sum=$((sum + n))
	done
	expect "backend packets add up to service hits" "$sum" -eq "$hits"
	expect "no packets to missing tables" "$(metric ferry_no_table_total)" -eq 0

	log "$mode: SIGHUP reload swaps the dns backends"
	sed -i 's/"10.42.0.20:53", "10.42.1.21:53"/"10.42.9.99:53"/' "$WORK/ferry.json"
	kill -HUP "$PID"
	wait_for "[ \$(metric ferry_backends) -eq 4 ]"
	expect "old dns backend retired" "$(metric ferry_backend_packets_total 'backend="10.42.0.20:53"')" -eq 0
	udp_flows 50
	expect "new flows reach the new backend" "$(metric ferry_backend_packets_total 'backend="10.42.9.99:53"')" -ge 50
	expect "reloads succeeded" "$(metric ferry_config_reloads_total 'result="success"')" -eq 2

	log "$mode: a bad config is rejected and the tables stay"
	echo '{"services": [' >"$WORK/ferry.json"
	kill -HUP "$PID"
	wait_for "[ \$(metric ferry_config_reloads_total 'result=\"failure\"') -eq 1 ]"
	expect "still serving" "$(metric ferry_services)" -eq 2
	expect "last reload flagged" "$(metric ferry_config_last_reload_successful)" -eq 0
	before=$(metric ferry_service_hits_total)
	udp_flows 10
	expect "still steering" "$(metric ferry_service_hits_total)" -ge $((before + 10))

	log "$mode: SIGTERM detaches"
	kill -TERM "$PID"
	wait "$PID" || fail "ferry exited with status $?"
	PID=
	if ip link show dev "$IF" | grep -q 'prog/xdp'; then fail "XDP program still attached after exit"; fi
	printf 'ok   detached\n'
done

log "PASS ($MODES)"
