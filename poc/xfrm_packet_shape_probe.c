// SPDX-License-Identifier: GPL-2.0
// Passive tc-BPF packet-shape probe for decrypted IPsec/XFRM traffic on xfrm0.
//
// This version intentionally uses bpf_skb_load_bytes() instead of direct
// packet access, matching DAE's slow parser path more closely.
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
static long (*const bpf_skb_load_bytes)(const struct __sk_buff *skb,
					__u32 offset, void *to,
					__u32 len) = (void *)26;

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

static __always_inline int load_u8(struct __sk_buff *skb, __u32 offset, __u8 *value)
{
	*value = 0xff;
	return bpf_skb_load_bytes(skb, offset, value, sizeof(*value));
}

static __always_inline int parse_at_offset(struct __sk_buff *skb, __u32 hook_id,
					   __u32 offset, __u8 version)
{
	__u32 l3_offset = offset;

	if (version == 4) {
		struct iphdr iph = {};
		__u32 ihl;
		int ret;

		ret = bpf_skb_load_bytes(skb, l3_offset, &iph, sizeof(iph));
		if (ret) {
			bpf_printk("shape hook=%u ip4_load_err=%d off=%u\n",
				   hook_id, ret, l3_offset);
			return TC_ACT_PIPE;
		}

		ihl = (iph.ihl_version & 0x0f) * 4;
		if (ihl < sizeof(iph)) {
			bpf_printk("shape hook=%u ip4_bad_ihl ihl=%u off=%u\n",
				   hook_id, ihl, l3_offset);
			return TC_ACT_PIPE;
		}

		bpf_printk("shape hook=%u ip4 off=%u proto=%u\n",
			   hook_id, l3_offset, iph.protocol);
		bpf_printk("shape mark=0x%x ihl=%u len=%u\n",
			   skb->mark, ihl, skb->len);
		bpf_printk("shape sip=0x%x dip=0x%x\n",
			   bpf_ntohl(iph.saddr), bpf_ntohl(iph.daddr));

		if (iph.protocol == IPPROTO_TCP) {
			struct tcphdr tcp = {};
			__u8 syn_ack;

			ret = bpf_skb_load_bytes(skb, l3_offset + ihl, &tcp,
						 sizeof(tcp));
			if (ret) {
				bpf_printk("shape hook=%u tcp_load_err=%d off=%u\n",
					   hook_id, ret, l3_offset + ihl);
				return TC_ACT_PIPE;
			}

			syn_ack = (tcp.flags & 0x12);
			bpf_printk("shape tcp sport=%u dport=%u flags=0x%x\n",
				   bpf_ntohs(tcp.source), bpf_ntohs(tcp.dest),
				   tcp.flags);
			bpf_printk("shape tcp synack=0x%x seq=0x%x ack=0x%x\n",
				   syn_ack, bpf_ntohl(tcp.seq),
				   bpf_ntohl(tcp.ack_seq));
		} else if (iph.protocol == IPPROTO_UDP) {
			struct udphdr udp = {};

			ret = bpf_skb_load_bytes(skb, l3_offset + ihl, &udp,
						 sizeof(udp));
			if (ret) {
				bpf_printk("shape hook=%u udp_load_err=%d off=%u\n",
					   hook_id, ret, l3_offset + ihl);
				return TC_ACT_PIPE;
			}

			bpf_printk("shape udp sport=%u dport=%u len=%u\n",
				   bpf_ntohs(udp.source), bpf_ntohs(udp.dest),
				   bpf_ntohs(udp.len));
		}
	} else if (version == 6) {
		struct ipv6hdr ip6h = {};
		int ret;

		ret = bpf_skb_load_bytes(skb, l3_offset, &ip6h, sizeof(ip6h));
		if (ret) {
			bpf_printk("shape hook=%u ip6_load_err=%d off=%u\n",
				   hook_id, ret, l3_offset);
			return TC_ACT_PIPE;
		}

		bpf_printk("shape hook=%u ip6 off=%u nexthdr=%u\n",
			   hook_id, l3_offset, ip6h.nexthdr);
		bpf_printk("shape mark=0x%x len=%u\n", skb->mark, skb->len);
		bpf_printk("shape plen=%u if=%u ingress=%u\n",
			   bpf_ntohs(ip6h.payload_len), skb->ifindex,
			   skb->ingress_ifindex);
	} else {
		bpf_printk("shape hook=%u unexpected_version=%u off=%u\n",
			   hook_id, version, l3_offset);
	}

	return TC_ACT_PIPE;
}

static __always_inline int parse_l3_packet(struct __sk_buff *skb, __u32 hook_id)
{
	__u8 b0, b4, b8, b14;
	int r0, r4, r8, r14;

	r0 = load_u8(skb, 0, &b0);
	r4 = load_u8(skb, 4, &b4);
	r8 = load_u8(skb, 8, &b8);
	r14 = load_u8(skb, 14, &b14);

	bpf_printk("shape hook=%u scan r0=%d b0=0x%x\n",
		   hook_id, r0, b0);
	bpf_printk("shape scan r4=%d b4=0x%x r8=%d\n", r4, b4, r8);
	bpf_printk("shape scan b8=0x%x r14=%d b14=0x%x\n", b8, r14, b14);
	bpf_printk("shape proto=0x%x len=%u\n", skb->protocol, skb->len);
	bpf_printk("shape if=%u ingress=%u mark=0x%x\n",
		   skb->ifindex, skb->ingress_ifindex, skb->mark);

	if (!r0 && ((b0 >> 4) == 4 || (b0 >> 4) == 6))
		return parse_at_offset(skb, hook_id, 0, b0 >> 4);
	if (!r4 && ((b4 >> 4) == 4 || (b4 >> 4) == 6))
		return parse_at_offset(skb, hook_id, 4, b4 >> 4);
	if (!r8 && ((b8 >> 4) == 4 || (b8 >> 4) == 6))
		return parse_at_offset(skb, hook_id, 8, b8 >> 4);
	if (!r14 && ((b14 >> 4) == 4 || (b14 >> 4) == 6))
		return parse_at_offset(skb, hook_id, 14, b14 >> 4);

	bpf_printk("shape hook=%u no_ip_version_found len=%u\n",
		   hook_id, skb->len);
	return TC_ACT_PIPE;
}

SEC("tc/xfrm_shape_xfrm0_ingress")
int xfrm_shape_xfrm0_ingress(struct __sk_buff *skb)
{
	return parse_l3_packet(skb, 2);
}

SEC("license")
char __license[] = "GPL";
