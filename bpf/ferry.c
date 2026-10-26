// SPDX-License-Identifier: GPL-2.0
//
// Ferry XDP fast path: a full-NAT L4 load balancer on one interface.
//
// Client -> VIP: look up the VIP in `services`. Reuse the flow's tracked
// backend and SNAT port if the flow is still alive; otherwise hash the
// 5-tuple into the service's Maglev table and allocate a SNAT port. Rewrite
// to snat_ip:port -> backend and send it back out the same interface
// (XDP_TX), addressed to the next hop `bpf_fib_lookup` returns.
//
// Backend -> snat_ip:port: look the pair up in `nat` and rewrite to
// VIP -> client. Everything else goes to the kernel (XDP_PASS).
//
// Table swaps: `maglev_tables` is an ARRAY_OF_MAPS indexed by service id.
// The control plane fills a brand-new inner array and then replaces the outer
// slot with one map update. A program run that already looked up the old
// inner map keeps using it until it returns (RCU), so readers never see a
// half-written table.
//
// Flow state: `conntrack` maps a client flow to (backend, SNAT port). `nat`
// maps (backend, SNAT port) back to the client and decides whether a flow is
// alive: it holds the TCP state and when the flow last saw a packet, and an
// entry idle for longer than its state's timeout is dead and its port free.
//
// Shadow mode (`shadow`, set at load): select and count as above, keep
// conntrack, then XDP_PASS every packet unmodified. No NAT state.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2

// Keep in sync with internal/dataplane and internal/maglev.
#define MAGLEV_SIZE 16381
#define MAX_SERVICES 256
#define MAX_BACKENDS 1024
#define CT_ENTRIES 65536
#define NAT_ENTRIES 65536

// Random probes for a free SNAT port before giving up on a new flow.
#define SNAT_TRIES 32

// Idle timeouts by flow state, after IPVS and Linux conntrack. CLOSING is
// as long as Linux's TIME_WAIT, so a port isn't reused while the backend may
// still hold the old connection.
#define NSEC 1000000000ULL
#define TIMEOUT_TCP_NEW (60 * NSEC)
#define TIMEOUT_TCP_EST (900 * NSEC)
#define TIMEOUT_TCP_CLOSING (60 * NSEC)
#define TIMEOUT_TCP_CLOSED (10 * NSEC)
#define TIMEOUT_UDP_NEW (30 * NSEC)
#define TIMEOUT_UDP_EST (60 * NSEC)

// Set by the control plane at load time.
volatile const __be32 snat_ip = 0;
volatile const __u16 snat_port_min = 0; // host byte order
volatile const __u16 snat_port_max = 0;
volatile const __u8 shadow = 0;

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
	__be16 snat_port; // 0 in shadow mode
	__u16 pad;
};

struct nat_key {
	__be32 backend_ip;
	__be16 backend_port;
	__be16 snat_port;
	__u8 proto;
	__u8 pad[3];
};

enum flow_state {
	FLOW_NEW,     // no reply from the backend yet
	FLOW_EST,     // backend has replied
	FLOW_CLOSING, // FIN seen
	FLOW_CLOSED,  // RST seen
};

struct nat_entry {
	__be32 client_ip;
	__be32 vip;
	__be16 client_port;
	__be16 vip_port;
	__u8 state;
	__u8 pad[3];
	__u64 last_seen_ns;
};

enum stat {
	STAT_PACKETS,        // all packets seen
	STAT_SERVICE_HIT,    // destined to a known VIP
	STAT_CT_HIT,         // reused a tracked backend
	STAT_CT_RESELECT,    // tracked backend was inactive; picked a new one
	STAT_NO_TABLE,       // VIP known but no table installed (race or bug)
	STAT_NO_BACKEND,     // table slot pointed at an inactive backend
	STAT_FORWARDED,      // client packet sent to a backend
	STAT_REPLIED,        // backend packet sent to a client
	STAT_SNAT_EXHAUSTED, // dropped: no free SNAT port for the backend
	STAT_NO_NEIGH,       // dropped: next hop's MAC unknown
	STAT_FIB_FAIL,       // dropped: no usable route
	STAT_WRONG_IFACE,    // dropped: route leaves by another interface
	STAT_TTL_EXCEEDED,   // dropped: TTL would reach zero
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
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, NAT_ENTRIES);
	__type(key, struct nat_key);
	__type(value, struct nat_entry);
} nat SEC(".maps");

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

// A parsed packet. Header pointers are bounds-checked by parse().
struct packet {
	struct ethhdr *eth;
	struct iphdr *ip;
	__be16 *ports; // [0] source, [1] destination
	__u16 *check;  // TCP or UDP checksum
	struct tcphdr *tcp; // NULL for UDP
	struct flow_key fk;
};

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
// Finalized with murmur3's fmix32. Mirrored by Flow.Hash in Go.
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

// Incremental checksum update for one 16-bit word (RFC 1624, eqn. 3).
// One's-complement sums don't depend on byte order, so the arguments only
// have to agree with each other.
static __always_inline __u16 csum_replace2(__u16 check, __u16 from, __u16 to)
{
	__u32 sum = (__u16)~check + (__u16)~from + to;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

static __always_inline __u16 csum_replace4(__u16 check, __u32 from, __u32 to)
{
	check = csum_replace2(check, from >> 16, to >> 16);
	return csum_replace2(check, from & 0xffff, to & 0xffff);
}

static __always_inline int parse(struct xdp_md *ctx, struct packet *p)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	p->eth = data;
	if ((void *)(p->eth + 1) > data_end || p->eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	p->ip = (void *)(p->eth + 1);
	if ((void *)(p->ip + 1) > data_end || p->ip->ihl < 5)
		return -1;
	// Fragments carry no L4 header after the first; leave them to the kernel.
	if (p->ip->frag_off & bpf_htons(0x3fff))
		return -1;

	void *l4 = (void *)p->ip + p->ip->ihl * 4;
	if (p->ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		p->tcp = tcp;
		p->ports = &tcp->source;
		p->check = &tcp->check;
	} else if (p->ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		p->tcp = NULL;
		p->ports = &udp->source;
		p->check = &udp->check;
	} else {
		return -1;
	}

	p->fk.saddr = p->ip->saddr;
	p->fk.daddr = p->ip->daddr;
	p->fk.sport = p->ports[0];
	p->fk.dport = p->ports[1];
	p->fk.proto = p->ip->protocol;
	return 0;
}

// rewrite replaces the packet's addresses and ports, decrements the TTL, and
// patches the IP and L4 checksums to match.
static __always_inline void rewrite(struct packet *p, __be32 saddr, __be16 sport, __be32 daddr, __be16 dport)
{
	struct iphdr *ip = p->ip;
	__u16 ipc = ip->check;
	__u16 l4c = *p->check;
	// A zero UDP checksum means "none"; it stays that way.
	int l4 = p->tcp || l4c != 0;

	ipc = csum_replace4(ipc, ip->saddr, saddr);
	ipc = csum_replace4(ipc, ip->daddr, daddr);
	if (l4) {
		// The pseudo-header covers both addresses.
		l4c = csum_replace4(l4c, ip->saddr, saddr);
		l4c = csum_replace4(l4c, ip->daddr, daddr);
		l4c = csum_replace2(l4c, p->ports[0], sport);
		l4c = csum_replace2(l4c, p->ports[1], dport);
		if (!p->tcp && l4c == 0)
			l4c = 0xffff;
	}

	// TTL shares a 16-bit word with the protocol number.
	__u16 *ttl_word = (__u16 *)&ip->ttl;
	__u16 old = *ttl_word;
	ip->ttl--;
	ipc = csum_replace2(ipc, old, *ttl_word);

	ip->saddr = saddr;
	ip->daddr = daddr;
	ip->check = ipc;
	p->ports[0] = sport;
	p->ports[1] = dport;
	*p->check = l4c;
}

// route finds the next hop for a packet from saddr to daddr. On success it
// fills in the Ethernet addresses for XDP_TX and returns -1; otherwise it
// returns the XDP action to take.
static __always_inline int route(struct xdp_md *ctx, struct packet *p, __be32 saddr, __be32 daddr,
				 struct bpf_fib_lookup *fib)
{
	__builtin_memset(fib, 0, sizeof(*fib));
	fib->family = AF_INET;
	fib->tos = p->ip->tos;
	fib->l4_protocol = p->ip->protocol;
	fib->tot_len = bpf_ntohs(p->ip->tot_len);
	fib->ipv4_src = saddr;
	fib->ipv4_dst = daddr;
	fib->ifindex = ctx->ingress_ifindex;

	int rc = bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
	// One-armed: replies must arrive on this NIC, where the program can
	// reverse the NAT, so routes out of other interfaces are unusable.
	// The egress ifindex is filled in for NO_NEIGH as well.
	if ((rc == BPF_FIB_LKUP_RET_SUCCESS || rc == BPF_FIB_LKUP_RET_NO_NEIGH) &&
	    fib->ifindex != ctx->ingress_ifindex) {
		count(STAT_WRONG_IFACE);
		return XDP_DROP;
	}
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		return -1;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		// The control plane keeps backends' next hops resolved; the
		// sender will retransmit.
		count(STAT_NO_NEIGH);
		return XDP_DROP;
	default:
		count(STAT_FIB_FAIL);
		return XDP_DROP;
	}
}

static __always_inline int transmit(struct packet *p, struct bpf_fib_lookup *fib)
{
	__builtin_memcpy(p->eth->h_dest, fib->dmac, ETH_ALEN);
	__builtin_memcpy(p->eth->h_source, fib->smac, ETH_ALEN);
	return XDP_TX;
}

static __always_inline int expired(const struct nat_entry *n, __u8 proto, __u64 now)
{
	__u64 timeout;
	if (proto == IPPROTO_UDP) {
		timeout = n->state == FLOW_NEW ? TIMEOUT_UDP_NEW : TIMEOUT_UDP_EST;
	} else {
		switch (n->state) {
		case FLOW_NEW:
			timeout = TIMEOUT_TCP_NEW;
			break;
		case FLOW_EST:
			timeout = TIMEOUT_TCP_EST;
			break;
		case FLOW_CLOSING:
			timeout = TIMEOUT_TCP_CLOSING;
			break;
		default:
			timeout = TIMEOUT_TCP_CLOSED;
		}
	}
	return now - n->last_seen_ns > timeout;
}

// track advances a flow's state for one packet. Only the backend's packets
// can establish a flow.
static __always_inline void track(struct nat_entry *n, struct tcphdr *tcp, int from_backend, __u64 now)
{
	n->last_seen_ns = now;
	if (!tcp) {
		if (from_backend)
			n->state = FLOW_EST;
		return;
	}
	if (tcp->rst)
		n->state = FLOW_CLOSED;
	else if (tcp->fin)
		n->state = FLOW_CLOSING;
	else if (tcp->syn && !tcp->ack && !from_backend)
		n->state = FLOW_NEW; // client reusing the 5-tuple
	else if (from_backend && n->state == FLOW_NEW)
		n->state = FLOW_EST;
}

static __always_inline int owns(const struct nat_entry *n, const struct flow_key *fk)
{
	return n->client_ip == fk->saddr && n->client_port == fk->sport &&
	       n->vip == fk->daddr && n->vip_port == fk->dport;
}

// alloc_snat claims a free SNAT port toward backend b for the flow and
// returns it (network order), or 0 if none was found. Ports are only
// unique per backend address, since that is all a reply can be matched on.
static __always_inline __be16 alloc_snat(const struct backend *b, struct packet *p, __u64 now)
{
	struct nat_entry v = {
		.client_ip = p->fk.saddr,
		.vip = p->fk.daddr,
		.client_port = p->fk.sport,
		.vip_port = p->fk.dport,
		.state = FLOW_NEW,
		.last_seen_ns = now,
	};
	if (p->tcp && p->tcp->rst)
		v.state = FLOW_CLOSED;
	struct nat_key k = { .backend_ip = b->ip, .backend_port = b->port, .proto = p->fk.proto };
	__u32 range = (__u32)snat_port_max - snat_port_min + 1;

	for (int i = 0; i < SNAT_TRIES; i++) {
		k.snat_port = bpf_htons(snat_port_min + bpf_get_prandom_u32() % range);
		struct nat_entry *old = bpf_map_lookup_elem(&nat, &k);
		if (old) {
			if (!expired(old, k.proto, now))
				continue;
			// Delete, then insert with NOEXIST: if another CPU races us
			// for the same dead port, only one of us gets it.
			bpf_map_delete_elem(&nat, &k);
		}
		if (bpf_map_update_elem(&nat, &k, &v, BPF_NOEXIST) == 0)
			return k.snat_port;
	}
	return 0;
}

// release frees the SNAT port a tracked flow held toward a retired backend,
// if the port is still the flow's.
static __always_inline void release(const struct ct_entry *ct, const struct flow_key *fk)
{
	__u32 id = ct->backend_id;
	struct backend *old = bpf_map_lookup_elem(&backends, &id);
	if (!old || !ct->snat_port)
		return;
	struct nat_key k = { .backend_ip = old->ip, .backend_port = old->port, .snat_port = ct->snat_port, .proto = fk->proto };
	struct nat_entry *n = bpf_map_lookup_elem(&nat, &k);
	if (n && owns(n, fk))
		bpf_map_delete_elem(&nat, &k);
}

// reply reverses the NAT for a backend's packet to snat_ip. It returns -1
// if the packet doesn't belong to a live flow.
static __always_inline int reply(struct xdp_md *ctx, struct packet *p)
{
	struct nat_key k = {
		.backend_ip = p->fk.saddr,
		.backend_port = p->fk.sport,
		.snat_port = p->fk.dport,
		.proto = p->fk.proto,
	};
	struct nat_entry *n = bpf_map_lookup_elem(&nat, &k);
	__u64 now = bpf_ktime_get_ns();
	if (!n || expired(n, k.proto, now))
		return -1;
	if (p->ip->ttl <= 1) {
		count(STAT_TTL_EXCEEDED);
		return XDP_DROP;
	}
	struct bpf_fib_lookup fib;
	int action = route(ctx, p, n->vip, n->client_ip, &fib);
	if (action >= 0)
		return action;

	track(n, p->tcp, 1, now);
	rewrite(p, n->vip, n->vip_port, n->client_ip, n->client_port);
	count(STAT_REPLIED);
	return transmit(p, &fib);
}

SEC("xdp")
int ferry_ingress(struct xdp_md *ctx)
{
	count(STAT_PACKETS);

	struct packet p = {};
	if (parse(ctx, &p) < 0)
		return XDP_PASS;

	if (!shadow && p.fk.daddr == snat_ip) {
		__u16 port = bpf_ntohs(p.fk.dport);
		if (port >= snat_port_min && port <= snat_port_max) {
			int action = reply(ctx, &p);
			if (action >= 0)
				return action;
		}
	}

	struct service_key sk = { .vip = p.fk.daddr, .port = p.fk.dport, .proto = p.fk.proto };
	__u32 *svc_id = bpf_map_lookup_elem(&services, &sk);
	if (!svc_id)
		return XDP_PASS;
	count(STAT_SERVICE_HIT);

	__u64 now = bpf_ktime_get_ns();
	__u32 backend_id = 0;
	struct backend *be = NULL;
	struct nat_entry *n = NULL;
	__be16 snat_port = 0;

	struct ct_entry *ct = bpf_map_lookup_elem(&conntrack, &p.fk);
	if (ct) {
		be = backend_if_active(ct->backend_id);
		if (!be) {
			count(STAT_CT_RESELECT);
			if (!shadow)
				release(ct, &p.fk);
		} else if (!shadow) {
			// Tracked, but is the flow still alive and its port still ours?
			struct nat_key k = { .backend_ip = be->ip, .backend_port = be->port, .snat_port = ct->snat_port, .proto = p.fk.proto };
			n = bpf_map_lookup_elem(&nat, &k);
			if (!n || !owns(n, &p.fk) || expired(n, p.fk.proto, now)) {
				n = NULL;
				be = NULL; // start over as a new flow
			}
		}
		if (be) {
			backend_id = ct->backend_id;
			snat_port = ct->snat_port;
			count(STAT_CT_HIT);
		}
	}

	if (!be) {
		void *table = bpf_map_lookup_elem(&maglev_tables, svc_id);
		if (!table) {
			count(STAT_NO_TABLE);
			return XDP_PASS;
		}
		__u32 slot = flow_hash(&p.fk) % MAGLEV_SIZE;
		__u32 *id = bpf_map_lookup_elem(table, &slot);
		if (!id)
			return XDP_PASS;
		be = backend_if_active(*id);
		if (!be) {
			count(STAT_NO_BACKEND);
			return XDP_PASS;
		}
		backend_id = *id;
	}

	if (shadow) {
		if (!ct || ct->backend_id != backend_id) {
			struct ct_entry e = { .backend_id = backend_id };
			bpf_map_update_elem(&conntrack, &p.fk, &e, BPF_ANY);
		}
		__u64 *pkts = bpf_map_lookup_elem(&backend_packets, &backend_id);
		if (pkts)
			*pkts += 1;
		return XDP_PASS;
	}

	if (p.ip->ttl <= 1) {
		count(STAT_TTL_EXCEEDED);
		return XDP_DROP;
	}
	// Route before allocating, so an unroutable backend costs no state.
	struct bpf_fib_lookup fib;
	int action = route(ctx, &p, snat_ip, be->ip, &fib);
	if (action >= 0)
		return action;

	if (n) {
		track(n, p.tcp, 0, now);
	} else {
		snat_port = alloc_snat(be, &p, now);
		if (!snat_port) {
			count(STAT_SNAT_EXHAUSTED);
			return XDP_DROP;
		}
		struct ct_entry e = { .backend_id = backend_id, .snat_port = snat_port };
		bpf_map_update_elem(&conntrack, &p.fk, &e, BPF_ANY);
	}

	__u64 *pkts = bpf_map_lookup_elem(&backend_packets, &backend_id);
	if (pkts)
		*pkts += 1;
	rewrite(&p, snat_ip, snat_port, be->ip, be->port);
	count(STAT_FORWARDED);
	return transmit(&p, &fib);
}

char _license[] SEC("license") = "GPL";
