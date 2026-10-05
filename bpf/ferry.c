// SPDX-License-Identifier: GPL-2.0
//
// Ferry XDP fast path.
//
// Per packet: parse Eth/IPv4/TCP|UDP -> look up the VIP in `services` ->
// reuse the connection-tracked backend if it is still active, otherwise hash
// the 5-tuple into that service's Maglev table -> count it.
//
// Table swaps: `maglev_tables` is an ARRAY_OF_MAPS indexed by service id.
// The control plane fills a brand-new inner array and then replaces the outer
// slot with one map update. A program run that already looked up the old
// inner map keeps using it until it returns (RCU), so readers never see a
// half-written table.
//
// STATUS: selection only. Packets are counted against the chosen backend and
// then passed to the kernel (XDP_PASS). The rewrite + forward step is the
// next milestone; see docs/design.md.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Keep in sync with internal/dataplane and internal/maglev.
#define MAGLEV_SIZE 16381
#define MAX_SERVICES 256
#define MAX_BACKENDS 4096
#define CT_ENTRIES 65536

struct service_key {
	__be32 vip;
	__be16 port;
	__u8 proto;
	__u8 pad;
};

struct backend {
	__be32 ip;
	__be16 port;
	__u8 active;
	__u8 pad;
};

struct flow_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct ct_entry {
	__u32 backend_id;
	__u32 pad;
	__u64 last_seen_ns;
};

enum stat {
	STAT_PACKETS,       // all packets seen
	STAT_SERVICE_HIT,   // destined to a known VIP
	STAT_CT_HIT,        // reused a tracked backend
	STAT_CT_RESELECT,   // tracked backend was inactive; picked a new one
	STAT_NO_TABLE,      // VIP known but no table installed (race or bug)
	STAT_NO_BACKEND,    // table slot pointed at an inactive backend
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SERVICES);
	__type(key, struct service_key);
	__type(value, __u32); // service id
} services SEC(".maps");

struct maglev_inner {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAGLEV_SIZE);
	__type(key, __u32);
	__type(value, __u32); // backend id
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_SERVICES);
	__type(key, __u32); // service id
	__array(values, struct maglev_inner);
} maglev_tables SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend);
} backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CT_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct ct_entry);
} conntrack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, __u64); // packets steered to this backend
} backend_packets SEC(".maps");

static __always_inline void count(__u32 stat)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &stat);
	if (v)
		*v += 1;
}

static __always_inline __u32 rotl(__u32 x, int k)
{
	return (x << k) | (x >> (32 - k));
}

// Not cryptographic; it only needs to spread flows evenly over the table.
// Finalized with murmur3's fmix32.
static __always_inline __u32 flow_hash(const struct flow_key *k)
{
	__u32 h = 0x9747b28c;
	h = rotl(h ^ k->saddr, 13) * 5 + 0xe6546b64;
	h = rotl(h ^ k->daddr, 13) * 5 + 0xe6546b64;
	h = rotl(h ^ (((__u32)k->sport << 16) | k->dport), 13) * 5 + 0xe6546b64;
	h ^= k->proto;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

static __always_inline struct backend *backend_if_active(__u32 id)
{
	struct backend *b = bpf_map_lookup_elem(&backends, &id);
	return (b && b->active) ? b : NULL;
}

SEC("xdp")
int xdp_ferry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	count(STAT_PACKETS);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl < 5)
		return XDP_PASS;
	// Fragments carry no L4 header after the first; leave them to the kernel.
	if (ip->frag_off & bpf_htons(0x3fff))
		return XDP_PASS;

	struct flow_key fk = {
		.saddr = ip->saddr,
		.daddr = ip->daddr,
		.proto = ip->protocol,
	};
	void *l4 = (void *)ip + ip->ihl * 4;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		fk.sport = tcp->source;
		fk.dport = tcp->dest;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		fk.sport = udp->source;
		fk.dport = udp->dest;
	} else {
		return XDP_PASS;
	}

	struct service_key sk = { .vip = fk.daddr, .port = fk.dport, .proto = fk.proto };
	__u32 *svc_id = bpf_map_lookup_elem(&services, &sk);
	if (!svc_id)
		return XDP_PASS;
	count(STAT_SERVICE_HIT);

	__u64 now = bpf_ktime_get_ns();
	__u32 backend_id;
	struct backend *be = NULL;

	struct ct_entry *ct = bpf_map_lookup_elem(&conntrack, &fk);
	if (ct) {
		be = backend_if_active(ct->backend_id);
		if (be) {
			backend_id = ct->backend_id;
			ct->last_seen_ns = now;
			count(STAT_CT_HIT);
		} else {
			count(STAT_CT_RESELECT);
		}
	}

	if (!be) {
		void *table = bpf_map_lookup_elem(&maglev_tables, svc_id);
		if (!table) {
			count(STAT_NO_TABLE);
			return XDP_PASS;
		}
		__u32 slot = flow_hash(&fk) % MAGLEV_SIZE;
		__u32 *id = bpf_map_lookup_elem(table, &slot);
		if (!id)
			return XDP_PASS;
		be = backend_if_active(*id);
		if (!be) {
			count(STAT_NO_BACKEND);
			return XDP_PASS;
		}
		backend_id = *id;
		struct ct_entry e = { .backend_id = backend_id, .last_seen_ns = now };
		bpf_map_update_elem(&conntrack, &fk, &e, BPF_ANY);
	}

	__u64 *n = bpf_map_lookup_elem(&backend_packets, &backend_id);
	if (n)
		*n += 1;

	// TODO(forwarding): rewrite toward `be` and XDP_TX / bpf_redirect.
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
