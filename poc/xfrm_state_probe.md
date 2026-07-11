# XFRM tc-BPF probe POC

This POC checks whether `bpf_skb_get_xfrm_state()` can distinguish IPsec/XFRM
packets on the encrypted first pass and the decrypted post-XFRM pass.

The probe is passive:

- it does not modify packets;
- it does not set packet marks;
- it does not redirect;
- it does not drop;
- it returns `TC_ACT_PIPE`.

## Build

Use the manual GitHub Action:

```text
Actions -> Build XFRM BPF POC -> Run workflow
```

Download the `xfrm-bpf-poc` artifact and copy `xfrm_state_probe.o` to the
router.

## Attach

Attach after DAE on WAN ingress. DAE WAN ingress currently returns
`TC_ACT_PIPE`, so a later priority should still run:

```sh
tc qdisc add dev eth1 clsact 2>/dev/null || true
tc filter add dev eth1 ingress pref 10 bpf da obj xfrm_state_probe.o sec tc/xfrm_probe_eth1_ingress
```

Attach before DAE on `xfrm0` ingress, so the probe can still run even if DAE
later returns `TC_ACT_OK`:

```sh
tc filter show dev xfrm0 ingress
tc qdisc add dev xfrm0 clsact 2>/dev/null || true
tc filter add dev xfrm0 ingress pref 1 bpf da obj xfrm_state_probe.o sec tc/xfrm_probe_xfrm0_ingress
```

If `pref 1` is already used on `xfrm0` ingress, choose another free priority
lower than DAE `dae_lan_ingress_l3` priority `2`, or temporarily run only the
`eth1` probe first.

## Observe

In one shell:

```sh
cat /sys/kernel/debug/tracing/trace_pipe
```

Then connect the IKEv2 client and generate a small amount of traffic.

Hook ids:

- `hook=1`: `eth1` ingress.
- `hook=2`: `xfrm0` ingress.

Interpretation:

- `hook=1 none` on ESP or UDP/4500 is expected for the encrypted first pass.
- `hook=1 FOUND` means the decrypted post-XFRM packet is passing tc ingress on
  `eth1`.
- `hook=2 FOUND` means the decrypted packet is passing tc ingress on `xfrm0`.
- `hook=2 none` with client inner traffic would mean the packet is visible there
  but has no XFRM state at that hook.

## Cleanup

Remove only the POC filters:

```sh
tc filter del dev eth1 ingress pref 10
tc filter del dev xfrm0 ingress pref 1
```

Do not remove the `clsact` qdisc unless DAE is stopped and you intentionally
want to remove all tc filters from that interface.
