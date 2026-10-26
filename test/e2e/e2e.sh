#!/usr/bin/env bash
# End-to-end test: run the real ferry binary as a full-NAT load balancer in
# front of real TCP and UDP servers, and check connections work, survive a
# reload and a restart, and that detach cleans up.
#
#   netns ferry-e2e (one L2 segment)              host (ferry attached here)
#   ferry-e2e1: client  10.99.0.2   <-- veth -->  ferry-e2e0: 10.99.0.1 (SNAT)
#               backends 10.99.0.11-14                        10.99.0.240 (VIP)
#
# One-armed, like the edge host: packets come in and go back out of the same
# interface. The client ARPs for the VIP like any LAN client would.
#
# Needs root on Linux, plus iproute2, curl, ping and ethtool. On macOS,
# `make e2e` runs this inside the privileged builder container. Set
# FERRY_BIN and FERRY_E2ETOOL to test prebuilt binaries (`make e2e-native`
# does, so sudo never runs go); otherwise it builds them, which needs the
# generated BPF code.
set -euo pipefail

cd "$(dirname "$0")/../.."

MODES=${FERRY_E2E_MODES:-xdp-generic xdp-native}
NS=ferry-e2e
IF=ferry-e2e0
PEER=ferry-e2e1
SNAT=10.99.0.1
CLIENT=10.99.0.2
VIP=10.99.0.240
METRICS=127.0.0.1:19469
PIN=/sys/fs/bpf/ferry-e2e
WORK=$(mktemp -d)
PID=
SERVERS=
XDPPASS=

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
	[[ -n $SERVERS ]] && kill "$SERVERS" 2>/dev/null
	[[ -n $XDPPASS ]] && kill "$XDPPASS" 2>/dev/null
	[[ -n ${FERRY_BIN:-} ]] && "$FERRY_BIN" detach -iface "$IF" -pin-dir "$PIN" >/dev/null 2>&1
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
	for i in $(seq 100); do
		if eval "$1" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
	done
	fail "timed out waiting for: $1"
}

# client CMD ARGS... runs e2etool in the client's namespace from the client address.
client() {
	local cmd=$1
	shift
	ip netns exec "$NS" "$E2ETOOL" "$cmd" -from "$CLIENT" "$@"
}

attached() { ip link show dev "$IF" | grep -q 'prog/xdp'; }

start_ferry() {
	"$FERRY_BIN" attach -iface "$IF" -mode "$1" -snat-ip "$SNAT" -snat-ports 61000-61999 \
		-pin-dir "$PIN" -config "$WORK/ferry.json" -metrics-addr "$METRICS" >>"$WORK/ferry.log" 2>&1 &
	PID=$!
	wait_for "curl -fsS http://$METRICS/healthz"
}

stop_ferry() {
	kill -TERM "$PID"
	wait "$PID" || fail "ferry exited with status $?"
	PID=
}

if [[ -z ${FERRY_BIN:-} || -z ${FERRY_E2ETOOL:-} ]]; then
	log "build"
	go build -o "$WORK/ferry-bin" ./cmd/ferry
	go build -o "$WORK/e2etool" ./test/e2e/e2etool
	FERRY_BIN=$WORK/ferry-bin
	FERRY_E2ETOOL=$WORK/e2etool
fi
E2ETOOL=$(realpath "$FERRY_E2ETOOL")
FERRY_BIN=$(realpath "$FERRY_BIN")
"$FERRY_BIN" version
"$FERRY_BIN" check -config test/e2e/ferry.json

log "topology"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
ip netns add "$NS"
ip link add "$IF" type veth peer name "$PEER" netns "$NS"
ip addr add "$SNAT/24" dev "$IF"
ip addr add "$VIP/32" dev "$IF"
ip link set "$IF" up
sysctl -qw "net.ipv4.conf.$IF.forwarding=1"
ip -n "$NS" link set lo up
ip -n "$NS" link set "$PEER" up
for a in "$CLIENT" 10.99.0.11 10.99.0.12 10.99.0.13 10.99.0.14; do
	ip -n "$NS" addr add "$a/24" dev "$PEER"
done
# Locally sent packets on a veth carry only a partial checksum, completed by
# "offload" that native XDP bypasses. Real NICs receive full checksums, so
# make the senders compute them: that also tests the NAT checksum updates.
ip netns exec "$NS" ethtool -K "$PEER" tx off >/dev/null
# The ICMP errors checked below shouldn't depend on the kernel's rate limit.
ip netns exec "$NS" sysctl -qw net.ipv4.icmp_ratelimit=0
# A veth drops native XDP_TX frames unless its peer has XDP enabled too.
ip netns exec "$NS" "$E2ETOOL" xdp-pass "$PEER" &
XDPPASS=$!
ip netns exec "$NS" "$E2ETOOL" serve 10.99.0.11:8443 10.99.0.12:8443 10.99.0.13:8443 10.99.0.14:8443 \
	10.99.0.11:5353 10.99.0.12:5353 &
SERVERS=$!

for mode in $MODES; do
	log "$mode: attach"
	cp test/e2e/ferry.json "$WORK/ferry.json"
	: >"$WORK/ferry.log"
	start_ferry "$mode"
	attached || fail "no XDP program on $IF"
	expect "services programmed" "$(metric ferry_services)" -eq 3
	expect "backends active" "$(metric ferry_backends)" -eq 6

	log "$mode: non-VIP traffic is untouched"
	ip netns exec "$NS" ping -c 3 -i 0.2 -W 1 "$SNAT" >/dev/null || fail "ping to the host failed"
	printf 'ok   ping\n'

	log "$mode: connections through the VIP"
	client dial -proto tcp -addr "$VIP:443" -n 60 -want-servers 3 -want-seen "$SNAT" || fail "TCP through the VIP"
	client dial -proto udp -addr "$VIP:53" -n 60 -want-servers 2 -want-seen "$SNAT" || fail "UDP through the VIP"
	expect "packets to backends" "$(metric ferry_forwarded_packets_total 'direction="to_backend"')" -ge 300
	expect "packets to clients" "$(metric ferry_forwarded_packets_total 'direction="to_client"')" -ge 240
	for reason in snat_exhausted no_neighbor fib_failed wrong_interface ttl_exceeded; do
		expect "no $reason drops" "$(metric ferry_dropped_packets_total "reason=\"$reason\"")" -eq 0
	done

	log "$mode: ICMP errors reach the client"
	# 10.99.0.13 has nothing on port 5354, so its kernel answers with "port
	# unreachable", addressed to the SNAT address.
	client refused -addr "$VIP:54" || fail "port unreachable did not reach the client"
	expect "ICMP errors to clients" "$(metric ferry_icmp_errors_total 'direction="to_client"')" -ge 1

	log "$mode: a held connection survives a reload and a restart"
	rm -f "$WORK/ready" "$WORK/go"
	client hold -addr "$VIP:443" -ready "$WORK/ready" -go "$WORK/go" &
	HOLD=$!
	wait_for "[ -s $WORK/ready ]"
	printf 'ok   holding a connection to %s\n' "$(cat "$WORK/ready")"

	sed -i 's/"10.99.0.13:8443"\]/"10.99.0.13:8443", "10.99.0.14:8443"]/' "$WORK/ferry.json"
	kill -HUP "$PID"
	wait_for "[ \$(metric ferry_backends) -eq 7 ]"
	client dial -proto tcp -addr "$VIP:443" -n 60 -want-servers 4 >/dev/null || fail "new backend not used after reload"
	printf 'ok   reload added a backend\n'

	stop_ferry
	attached || fail "pinned program was detached when ferry stopped"
	client dial -proto tcp -addr "$VIP:443" -n 20 -want-seen "$SNAT" >/dev/null || fail "forwarding stopped with the daemon"
	printf 'ok   still forwarding with the daemon stopped\n'

	start_ferry "$mode"
	grep -q "replaced program in place" "$WORK/ferry.log" || fail "restart did not reuse the pinned attachment"
	grep -q "restored data plane state" "$WORK/ferry.log" || fail "restart did not restore state"
	touch "$WORK/go"
	wait "$HOLD" || fail "held connection did not survive"
	client dial -proto tcp -addr "$VIP:443" -n 60 -want-servers 4 >/dev/null || fail "TCP after restart"
	printf 'ok   new connections after restart\n'

	log "$mode: a bad config is rejected and the tables stay"
	echo '{"services": [' >"$WORK/ferry.json"
	kill -HUP "$PID"
	wait_for "[ \$(metric ferry_config_reloads_total 'result=\"failure\"') -eq 1 ]"
	expect "still serving" "$(metric ferry_services)" -eq 3
	client dial -proto udp -addr "$VIP:53" -n 10 -want-servers 2 >/dev/null || fail "UDP after a rejected reload"
	printf 'ok   still forwarding\n'

	log "$mode: detach"
	stop_ferry
	"$FERRY_BIN" detach -iface "$IF" -pin-dir "$PIN"
	if attached; then fail "XDP program still attached after detach"; fi
	[[ ! -e $PIN/$IF ]] || fail "pinned state left in $PIN/$IF"
	printf 'ok   detached and unpinned\n'
done

log "PASS ($MODES)"
