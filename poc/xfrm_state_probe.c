// SPDX-License-Identifier: GPL-2.0
// Minimal tc-BPF probe for checking bpf_skb_get_xfrm_state() on IPsec/XFRM packets.
//
// Safety:
// - does not modify skb data;
// - does not set skb->mark;
// - does not redirect;
// - never drops packets;
// - returns TC_ACT_PIPE so later tc filters can still run.

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;

#define TC_ACT_PIPE 3

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

struct bpf_xfrm_state {
	__u32 reqid;
	__u32 spi;
	__u16 family;
	__u16 ext;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
};

static long (*const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;
static long (*const bpf_skb_get_xfrm_state)(struct __sk_buff *skb, __u32 index,
					    struct bpf_xfrm_state *xfrm_state,
					    __u32 size, __u64 flags) = (void *)66;

#define bpf_printk(fmt, ...) ({				\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

static __always_inline int probe_xfrm(struct __sk_buff *skb, __u32 hook_id)
{
	struct bpf_xfrm_state xs = {};
	long ret;

	ret = bpf_skb_get_xfrm_state(skb, 0, &xs, sizeof(xs), 0);
	if (ret == 0) {
		bpf_printk("xfrm_probe hook=%u FOUND if=%u ingress=%u\n",
			   hook_id, skb->ifindex, skb->ingress_ifindex);
		bpf_printk("xfrm_probe mark=0x%x proto=0x%x reqid=%u\n",
			   skb->mark, skb->protocol, xs.reqid);
		bpf_printk("xfrm_probe spi=0x%x family=%u\n",
			   xs.spi, xs.family);
	} else {
		bpf_printk("xfrm_probe hook=%u none ret=%d if=%u\n",
			   hook_id, (__s32)ret, skb->ifindex);
		bpf_printk("xfrm_probe ingress=%u mark=0x%x proto=0x%x\n",
			   skb->ingress_ifindex, skb->mark, skb->protocol);
	}

	return TC_ACT_PIPE;
}

SEC("tc/xfrm_probe_eth1_ingress")
int xfrm_probe_eth1_ingress(struct __sk_buff *skb)
{
	return probe_xfrm(skb, 1);
}

SEC("tc/xfrm_probe_xfrm0_ingress")
int xfrm_probe_xfrm0_ingress(struct __sk_buff *skb)
{
	return probe_xfrm(skb, 2);
}

SEC("license")
char __license[] = "GPL";
