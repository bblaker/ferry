# Deploying Ferry

Ferry runs as one systemd service on the edge host. It attaches an XDP
program to one interface and load-balances TCP and UDP to the VIPs in its
config with full NAT: clients talk to the VIP, backends see connections from
the edge host's address, and both directions pass through Ferry. See
[design.md](design.md#forwarding-one-armed-full-nat) for how.

## Requirements

- **Linux 5.9 or newer** on arm64 (or amd64). Ferry uses `bpf_link` for XDP
  (5.9), and `CAP_BPF`/`CAP_PERFMON` (5.8). Raspberry Pi OS Bookworm ships a
  6.x kernel.
- **A NIC whose driver supports native XDP**, for `-mode xdp-native`. Ferry
  asks for driver mode explicitly and fails at startup if the driver can't do
  it, instead of quietly falling back. `ethtool -i <iface>` shows the driver;
  if native attach fails, use `xdp-generic` (same behaviour, much slower).
- **One-armed topology.** Clients, the VIPs and the backends' next hops must
  all be reachable through the one interface Ferry is attached to. Backends
  routed out of another interface, and backends on the edge host itself,
  aren't supported. Ferry logs a warning for backends routed elsewhere and
  counts their packets as `wrong_interface` drops.
- **The VIPs and the SNAT address on that interface.** Add each VIP to the
  interface (`ip addr add 192.168.1.240/32 dev enp3s0`, or your network
  config's equivalent) so the host answers ARP for it. The SNAT address is
  the host's own address there; backends reply to it.
- **IPv4 forwarding on the interface**, which `bpf_fib_lookup` requires, and
  the **SNAT ports reserved** from the kernel's ephemeral range. Ferry checks
  both at startup; `deploy/90-ferry.conf` sets them.
- **bpffs at `/sys/fs/bpf`** (systemd mounts it), where Ferry pins its state.
- **Capabilities** `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`. The unit runs as
  uid 0 (the pin directory is root-only) but with only these three. Without
  `CAP_PERFMON` the verifier rejects the program.

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
scp bin/ferry-linux-arm64 deploy/ferry.service deploy/90-ferry.conf \
    deploy/ferry.example.json edge:/tmp/

# on the edge host
sudo install -m 0755 /tmp/ferry-linux-arm64 /usr/local/bin/ferry

sudo install -m 0644 /tmp/90-ferry.conf /etc/sysctl.d/90-ferry.conf
sudoedit /etc/sysctl.d/90-ferry.conf          # eth0 -> your interface
sudo sysctl --system

sudo ip addr add 192.168.1.240/32 dev enp3s0  # each VIP; persist it in your network config

sudo install -d /etc/ferry
sudo install -m 0644 /tmp/ferry.example.json /etc/ferry/ferry.json
sudoedit /etc/ferry/ferry.json                # real VIPs and backends
ferry check -config /etc/ferry/ferry.json

sudo tee /etc/default/ferry <<'EOF'
FERRY_IFACE=enp3s0
FERRY_MODE=xdp-native
FERRY_SNAT_IP=192.168.1.10
FERRY_METRICS_ADDR=127.0.0.1:9469
FERRY_FLAGS=-shadow
EOF

sudo install -m 0644 /tmp/ferry.service /etc/systemd/system/ferry.service
sudo systemctl daemon-reload
sudo systemctl enable --now ferry
```

`FERRY_SNAT_IP` is required when the interface has more than one IPv4
address, which it will once the VIPs are on it. Set `FERRY_METRICS_ADDR` to a
LAN address (e.g. `192.168.1.10:9469`) if Prometheus scrapes from another
host. Metrics include backend addresses, so don't bind a public interface.

### Roll out in shadow mode first

The example above starts with `FERRY_FLAGS=-shadow`. Ferry then selects
backends and counts packets but hands every packet to the kernel unchanged,
so it can't break anything. Check that `ferry_service_hits_total` and the
per-backend counters look right, then turn forwarding on:

```sh
sudo sed -i 's/^FERRY_FLAGS=.*/FERRY_FLAGS=/' /etc/default/ferry
sudo systemctl restart ferry
```

Flows Ferry tracked in shadow mode become new flows; nothing needs
resetting.

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
journalctl -u ferry -b      # "forwarding snat=...", "loaded ... insns=", "attached", "ferry running"
ip link show dev enp3s0     # shows xdp (or xdpgeneric) and prog/xdp id N
curl -s localhost:9469/metrics | grep -v '^#'
```

From a client, connect to a VIP. `ferry_forwarded_packets_total` should rise
in both directions, and the backend should see the connection come from the
SNAT address. Every `ferry_dropped_packets_total` reason should stay at 0.

For a closer look (needs `bpftool`):

```sh
sudo bpftool prog show name ferry_ingress
sudo bpftool map dump pinned /sys/fs/bpf/ferry/enp3s0/services
sudo bpftool map dump pinned /sys/fs/bpf/ferry/enp3s0/nat | head
```

## Operate

**Change backends or services:** edit `/etc/ferry/ferry.json`, then
`sudo systemctl reload ferry`. The reload runs `ferry check` first, so a bad
file fails the `systemctl` command and the running tables stay as they were.
Tracked flows keep their backend across the swap. Flows on a removed backend
are sent to a new one, which resets them, so clients reconnect promptly.

**Restart or upgrade:** install the new binary and
`sudo systemctl restart ferry`. Ferry's maps and XDP attachment are pinned
under `/sys/fs/bpf/ferry/`, so the old program keeps forwarding while the
daemon is down. The new one is swapped in atomically and adopts the existing
flow state: established connections survive. If the new build changed a map
layout, startup fails with "incompatible build"; then
`sudo ferry detach -iface enp3s0` and start again, which drops tracked flows.

**Stop:** `sudo systemctl stop ferry` stops the control plane only. **The
program keeps forwarding** with its last tables, which is what makes
restarts safe, but config changes and backend health no longer reach it. To
take Ferry out of the path:

```sh
sudo systemctl disable --now ferry
sudo ferry detach -iface enp3s0    # traffic to the VIPs now goes to the kernel
```

**Roll back:** install the previous binary and restart, as for an upgrade.

### Metrics

| metric | type | meaning |
|---|---|---|
| `ferry_packets_total` | counter | every packet the XDP program saw |
| `ferry_service_hits_total` | counter | packets to a configured VIP:port/proto |
| `ferry_conntrack_hits_total` | counter | packets of a tracked, live flow |
| `ferry_conntrack_reselects_total` | counter | tracked flows whose backend was retired, rehashed |
| `ferry_forwarded_packets_total{direction}` | counter | NATed and sent: `to_backend`, `to_client` |
| `ferry_dropped_packets_total{reason}` | counter | see below; all should stay 0 |
| `ferry_no_table_total` | counter | VIP known but no table installed (should stay 0) |
| `ferry_no_backend_total` | counter | slot pointed at an inactive backend (should stay 0) |
| `ferry_backend_packets_total{backend}` | counter | client packets sent to each active backend |
| `ferry_services`, `ferry_backends` | gauge | programmed services, active backends |
| `ferry_config_reloads_total{result}` | counter | config applications, `success` / `failure` |
| `ferry_config_last_reload_successful` | gauge | 0 after a rejected or failed reload |
| `ferry_config_last_reload_success_timestamp_seconds` | gauge | time of last good apply |
| `ferry_build_info{version,goversion}` | gauge | always 1 |

Drop reasons:

| reason | meaning |
|---|---|
| `snat_exhausted` | no free SNAT port toward a backend: >20000 live flows to it, or a too-small `-snat-ports` |
| `no_neighbor` | next hop's MAC not resolved yet; the sender retransmits |
| `fib_failed` | no usable route to the backend or client |
| `wrong_interface` | the route leaves by another interface (unsupported topology) |
| `ttl_exceeded` | TTL would reach 0 |

Counters live in the pinned maps, so they survive restarts and reset on
`ferry detach`.

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
      - alert: FerryDropping
        expr: sum by (reason) (rate(ferry_dropped_packets_total[5m])) > 0
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
| `IPv4 forwarding is off on …` | Install `deploy/90-ferry.conf` (or `sysctl net.ipv4.conf.<iface>.forwarding=1`). |
| `SNAT ports … overlap the kernel's ephemeral ports` | Reserve them (`net.ipv4.ip_local_reserved_ports`, in `90-ferry.conf`) or pick `-snat-ports` outside `ip_local_port_range`. |
| `… has several IPv4 addresses; choose one with -snat-ip` | Set `FERRY_SNAT_IP` to the host's own address on the interface. |
| `pinned maps … are from an incompatible build` | A new build changed a map layout. `ferry detach -iface <iface>` (drops tracked flows), then start. |
| `attach xdp to …: … operation not supported` | The driver has no native XDP. Use `FERRY_MODE=xdp-generic`, or a NIC whose driver supports it. Switching modes needs `ferry detach` first. |
| `attach xdp …: device or resource busy` | Another XDP program is attached (`ip link show dev …`). If it was attached with `ip link`, remove it with `sudo ip link set dev <iface> xdp off`. |
| `verifier rejected ferry_ingress` with a long log | The full verifier log is in the journal. Check the kernel version and that `CAP_PERFMON` is granted. |
| clients time out, `ferry_service_hits_total` stays 0 | Traffic for the VIP isn't reaching the interface: is the VIP on the interface and answering ARP? Do `vip`/`proto` match what clients send? |
| clients time out, `to_backend` rises but `to_client` doesn't | Backends' replies aren't coming back through Ferry: they must reach the SNAT address via this interface. |
| `no_neighbor` drops keep rising | A backend's next hop doesn't answer ARP. Check the backend address and the route to it. |
| `wrong_interface` drops, or "routed out of another interface" in the log | The backend is reachable only via another interface. Ferry is one-armed; see Requirements. |
| backends log the edge host's address, not the client's | Expected with full NAT. The client address comes back with the L7 path (see todo.md). |
