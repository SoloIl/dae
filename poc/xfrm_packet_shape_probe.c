// SPDX-License-Identifier: GPL-2.0
// Passive tc-BPF packet-shape probe for decrypted IPsec/XFRM traffic on xfrm0.
//
// Safety:
// - does not modify skb data;
// - does not set skb->mark;
// - does not redirect;
// - never drops packets;
// - returns TC_ACT_PIPE so DAE's tc filter can still run after it.

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned int __be32;
typedef unsigned short __be16;

#define TC_ACT_PIPE 3
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
};

struct iphdr {
	__u8 ihl_version;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__be32 flow_lbl;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_res;
	__u8 flags;
	__be16 window;
	__be16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

static long (*const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

#define bpf_printk(fmt, ...) ({				\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

static __always_inline __u16 bpf_ntohs(__be16 v)
{
	return __builtin_bswap16(v);
}

static __always_inline __u32 bpf_ntohl(__be32 v)
{
	return __builtin_bswap32(v);
}

static __always_inline int parse_l3_packet(struct __sk_buff *skb, __u32 hook_id)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + 1 > data_end) {
		bpf_printk("shape hook=%u short if=%u ingress=%u\n",
			   hook_id, skb->ifindex, skb->ingress_ifindex);
		return TC_ACT_PIPE;
	}

	__u8 version = (*(__u8 *)data) >> 4;

	if (version == 4) {
		struct iphdr *iph = data;
		__u32 ihl;
		void *l4;

		if ((void *)(iph + 1) > data_end) {
			bpf_printk("shape hook=%u ip4_short if=%u ingress=%u\n",
				   hook_id, skb->ifindex, skb->ingress_ifindex);
			return TC_ACT_PIPE;
		}

		ihl = (iph->ihl_version & 0x0f) * 4;
		if (ihl < sizeof(*iph) || data + ihl > data_end) {
			bpf_printk("shape hook=%u ip4_bad_ihl ihl=%u mark=0x%x\n",
				   hook_id, ihl, skb->mark);
			return TC_ACT_PIPE;
		}

		bpf_printk("shape hook=%u ip4 proto=%u mark=0x%x\n",
			   hook_id, iph->protocol, skb->mark);
		bpf_printk("shape if=%u ingress=%u ihl=%u\n",
			   skb->ifindex, skb->ingress_ifindex, ihl);
		bpf_printk("shape sip=0x%x dip=0x%x\n",
			   bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));

		l4 = data + ihl;
		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp = l4;
			__u8 syn_ack;

			if ((void *)(tcp + 1) > data_end) {
				bpf_printk("shape hook=%u tcp_short mark=0x%x\n",
					   hook_id, skb->mark);
				return TC_ACT_PIPE;
			}

			syn_ack = (tcp->flags & 0x12);
			bpf_printk("shape tcp sport=%u dport=%u flags=0x%x\n",
				   bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest),
				   tcp->flags);
			bpf_printk("shape tcp synack=0x%x seq=0x%x ack=0x%x\n",
				   syn_ack, bpf_ntohl(tcp->seq),
				   bpf_ntohl(tcp->ack_seq));
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udp = l4;

			if ((void *)(udp + 1) > data_end) {
				bpf_printk("shape hook=%u udp_short mark=0x%x\n",
					   hook_id, skb->mark);
				return TC_ACT_PIPE;
			}

			bpf_printk("shape udp sport=%u dport=%u len=%u\n",
				   bpf_ntohs(udp->source), bpf_ntohs(udp->dest),
				   bpf_ntohs(udp->len));
		}
	} else if (version == 6) {
		struct ipv6hdr *ip6h = data;

		if ((void *)(ip6h + 1) > data_end) {
			bpf_printk("shape hook=%u ip6_short if=%u ingress=%u\n",
				   hook_id, skb->ifindex, skb->ingress_ifindex);
			return TC_ACT_PIPE;
		}

		bpf_printk("shape hook=%u ip6 nexthdr=%u mark=0x%x\n",
			   hook_id, ip6h->nexthdr, skb->mark);
		bpf_printk("shape if=%u ingress=%u plen=%u\n",
			   skb->ifindex, skb->ingress_ifindex,
			   bpf_ntohs(ip6h->payload_len));
	} else {
		bpf_printk("shape hook=%u unknown_l3=%u if=%u\n",
			   hook_id, version, skb->ifindex);
		bpf_printk("shape ingress=%u mark=0x%x proto=0x%x\n",
			   skb->ingress_ifindex, skb->mark, skb->protocol);
	}

	return TC_ACT_PIPE;
}

SEC("tc/xfrm_shape_xfrm0_ingress")
int xfrm_shape_xfrm0_ingress(struct __sk_buff *skb)
{
	return parse_l3_packet(skb, 2);
}

SEC("license")
char __license[] = "GPL";
