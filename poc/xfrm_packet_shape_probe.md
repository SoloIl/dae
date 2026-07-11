# XFRM packet-shape tc-BPF probe

This POC runs before DAE on `xfrm0` ingress and prints the visible L3/L4 packet
shape. It reads packet bytes with `bpf_skb_load_bytes()` to mirror DAE's slow
parser path more closely than direct packet access.

It is passive:

- it does not modify packets;
- it does not set packet marks;
- it does not redirect;
- it does not drop;
- it returns `TC_ACT_PIPE`.

## Build

Use the GitHub Action artifact from:

```text
Actions -> Build XFRM BPF POC
```

The artifact should include:

```text
xfrm_state_probe.o
xfrm_packet_shape_probe.o
```

## Attach

Attach before DAE on `xfrm0` ingress:

```sh
tc filter show dev xfrm0 ingress
tc filter add dev xfrm0 ingress pref 1 bpf da obj /root/xfrm_packet_shape_probe.o sec tc/xfrm_shape_xfrm0_ingress
```

## Observe

In one shell:

```sh
grep 'shape ' /sys/kernel/debug/tracing/trace_pipe
```

Then connect the IKEv2 client and generate a small amount of traffic.

Useful fields:

- `scan ... b0/b4/b8/b14`: first byte visible at candidate L3 offsets;
- `ip4 off=...`: IPv4 header found at that offset;
- `ip4 proto=6`: TCP;
- `ip4 proto=17`: UDP;
- `sip` / `dip`: IPv4 addresses in hexadecimal host byte order;
- `tcp flags=0x02`: TCP SYN;
- `tcp flags=0x12`: TCP SYN+ACK;
- `mark`: skb mark before DAE sees the packet.

## Cleanup

```sh
tc filter del dev xfrm0 ingress pref 1
```
