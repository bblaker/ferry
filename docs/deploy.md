# Deploying Ferry

Ferry runs as one systemd service on the edge host. Today it is in **shadow
mode**: it picks a backend for every packet to a VIP and counts it, then hands
the packet to the kernel unchanged (`XDP_PASS`). Deploying it cannot break
traffic. That makes now a good time to install it, watch its counters, and
confirm the NIC and kernel behave before forwarding lands (see
[todo.md](todo.md)).

## Requirements

- **Linux 5.9 or newer** on arm64 (or amd64). Ferry uses `bpf_link` for XDP
  (5.9), and `CAP_BPF`/`CAP_PERFMON` (5.8). Raspberry Pi OS Bookworm ships a
  6.x kernel.
- **A NIC whose driver supports native XDP**, for `-mode xdp-native`. Ferry
  asks for driver mode explicitly and fails at startup if the driver can't do
  it, instead of quietly falling back. `ethtool -i <iface>` shows the driver;
  if native attach fails, use `xdp-generic` (same behaviour, slower) until the
  hardware question is settled.
- **Capabilities** `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`. Root is not
  needed. Without `CAP_PERFMON` the verifier rejects the program (Spectre
  hardening for unprivileged loaders). The unit below grants exactly these
  three.
- The VIPs must be routed to this host (static route, ARP/NDP announcement,
  MetalLB, …). Ferry only sees packets that reach its interface.

## Build

On the dev machine (macOS needs Docker running):

```sh
make generate                 # compile bpf/ferry.c
make check test-bpf e2e       # unit, in-kernel and end-to-end tests
make build-linux              # bin/ferry-linux-arm64 (GOARCH=amd64 for x86)
```

CI builds the same binary on every push to `main`; it's attached to the
workflow run as `ferry-linux-arm64`.

## Install

```sh
scp bin/ferry-linux-arm64 deploy/ferry.service deploy/ferry.example.json edge:/tmp/

# on the edge host
sudo install -m 0755 /tmp/ferry-linux-arm64 /usr/local/bin/ferry
sudo install -d /etc/ferry
sudo install -m 0644 /tmp/ferry.example.json /etc/ferry/ferry.json
sudoedit /etc/ferry/ferry.json           # real VIPs and backends
ferry check -config /etc/ferry/ferry.json

sudo tee /etc/default/ferry <<'EOF'
FERRY_IFACE=enp3s0
FERRY_MODE=xdp-native
FERRY_METRICS_ADDR=127.0.0.1:9469
EOF

sudo install -m 0644 /tmp/ferry.service /etc/systemd/system/ferry.service
sudo systemctl daemon-reload
sudo systemctl enable --now ferry
```

Set `FERRY_METRICS_ADDR` to a LAN address (e.g. `192.168.1.10:9469`) if
Prometheus scrapes from another host. Metrics include backend addresses, so
don't bind a public interface.

### Config format

```json
{
  "services": [
    {
      "name": "ingress-https",
      "vip": "192.168.1.240:443",
      "proto": "tcp",
      "backends": ["10.42.0.11:8443", "10.42.1.12:8443"]
    }
  ]
}
```

`proto` is `tcp` (default) or `udp`. Names and VIP/port/proto triples must be
unique. Only unicast IPv4 with nonzero ports is accepted. Unknown fields are
errors: a misspelled `backends` would otherwise read as "no backends", and a
service with no backends is removed from the data plane. Limits are 256
services and 1024 backends (counting, during a reload, both the old and new
backends).

## Verify

```sh
systemctl status ferry
journalctl -u ferry -b                   # "loaded ... insns=", "attached", "ferry running"
ip link show dev enp3s0                  # shows xdp (or xdpgeneric) and prog/xdp id N
curl -s localhost:9469/healthz
curl -s localhost:9469/metrics | grep -v '^#'
```

Send some traffic to a VIP and check `ferry_service_hits_total` and the
per-backend `ferry_backend_packets_total{backend="..."}` go up, roughly evenly
across backends.

For a closer look (needs `bpftool`):

```sh
sudo bpftool prog show name ferry_ingress
sudo bpftool map dump name services
sudo bpftool map dump name conntrack | head
```

## Operate

**Change backends or services:** edit `/etc/ferry/ferry.json`, then
`sudo systemctl reload ferry`. The reload runs `ferry check` first, so a bad
file fails the `systemctl` command and the running tables stay as they were.
Tracked flows keep their backend across the swap; flows on a removed backend
are rehashed onto the new table.

**Upgrade:** install the new binary and `sudo systemctl restart ferry`. A
restart detaches the program for a moment and starts with empty conntrack.
In shadow mode that changes nothing for traffic. Once forwarding exists,
restarts must keep state, which needs map pinning (see todo.md).

**Stop or roll back:** `sudo systemctl stop ferry`. Ferry holds its XDP
attachment as a `bpf_link` owned by the process, so when the process exits for
any reason (stop, crash, `kill -9`), the kernel detaches the program and
traffic goes straight to the stack. To roll back, install the previous binary
and restart.

### Metrics

| metric | type | meaning |
|---|---|---|
| `ferry_packets_total` | counter | every packet the XDP program saw |
| `ferry_service_hits_total` | counter | packets to a configured VIP:port/proto |
| `ferry_conntrack_hits_total` | counter | packets that reused a tracked backend |
| `ferry_conntrack_reselects_total` | counter | tracked flows whose backend was retired, rehashed |
| `ferry_no_table_total` | counter | VIP known but no table installed (should stay 0) |
| `ferry_no_backend_total` | counter | slot pointed at an inactive backend (should stay 0) |
| `ferry_backend_packets_total{backend}` | counter | packets steered to each active backend |
| `ferry_services`, `ferry_backends` | gauge | programmed services, active backends |
| `ferry_config_reloads_total{result}` | counter | config applications, `success` / `failure` |
| `ferry_config_last_reload_successful` | gauge | 0 after a rejected or failed reload |
| `ferry_config_last_reload_success_timestamp_seconds` | gauge | time of last good apply |
| `ferry_build_info{version,goversion}` | gauge | always 1 |

Counters reset when Ferry restarts (the BPF maps are recreated).

Prometheus scrape config and starter alerts:

```yaml
scrape_configs:
  - job_name: ferry
    static_configs:
      - targets: ["edge:9469"]

groups:
  - name: ferry
    rules:
      - alert: FerryDown
        expr: up{job="ferry"} == 0
        for: 2m
      - alert: FerryReloadFailed
        expr: ferry_config_last_reload_successful == 0
        for: 5m
      - alert: FerryInconsistentTables
        expr: rate(ferry_no_table_total[5m]) > 0 or rate(ferry_no_backend_total[5m]) > 0
        for: 5m
```

`/healthz` returns 200 whenever the daemon is up and its tables are
programmed. If the latest reload was rejected, the body says so but the
status stays 200: the old tables are still serving.

## Troubleshooting

| symptom | cause and fix |
|---|---|
| `attach xdp to … (xdp-native): … operation not supported` | The driver has no native XDP. Use `FERRY_MODE=xdp-generic`, or a NIC whose driver supports it. |
| `attach xdp …: device or resource busy` | Another XDP program is attached (`ip link show dev …`). If it was attached with `ip link`, remove it with `sudo ip link set dev <iface> xdp off`. |
| `verifier rejected ferry_ingress` with a long log | The full verifier log is in the journal. Check the kernel version and that `CAP_PERFMON` is granted. |
| `operation not permitted` while loading | A missing capability, or a kernel older than 5.8 (no `CAP_BPF`). |
| `ferry_service_hits_total` stays 0 | Traffic to the VIP isn't reaching this interface. Check routing/ARP for the VIP, and that `vip`/`proto` match what clients send. |
| one backend gets no packets | Expected only with very few flows: Maglev balances flows, not packets. |
