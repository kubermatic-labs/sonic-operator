# EVPN/VXLAN hardware compatibility

This page lists the hardware on which the [EVPN/VXLAN](evpn-vxlan.md) feature has been tested, the known limitations, and what a test must show before a platform can be considered qualified.

## Support status

**No platform is hardware-qualified for EVPN/VXLAN.** No VXLAN packet delivery has been demonstrated, and no EVPN session has been activated on hardware.

## Tested hardware

| Item | Value |
| --- | --- |
| Platform | Dell Z9100 |
| ASIC | Broadcom BCM56960_B1 |
| SONiC | 202511 |
| SAI / SDK | libsaibcm 14.3.0.0.0.0.35.0, SDK 6.5.34-SP1 (legacy VXLAN path) |
| FRR | 10.4.1 |
| Result | Not qualified: VLAN/VNI map entry creation rejected by SAI |

The test used production agent RPCs over mTLS, not full Kubernetes controller reconciliation.

### What worked

- Forward and reverse FRR migrations (Traditional ↔ Unified), including native daemon and persistence checks.
- BGP parents (`Down`) and static routes reached configuration, persistence and runtime readiness.
- The source tunnel/NVO, VLAN/VNI mappings and explicit peer policies were staged and persisted.
- The switch created the SAI tunnel, tunnel map and termination objects.
- Runtime checks correctly withheld readiness when hardware was missing, and EVPN peers stayed shut down.
- All trial configuration was removed in native dependency order, and running and saved configuration matched the pre-test state without a reboot.

### What failed

Creating each `VNI_TO_VLAN` map entry failed in the Broadcom SAI:

```text
SAI_API_TUNNEL:_brcm_sai_vxlan_create_vpn:912
create tunnel initiator setup for net port failed with error Invalid parameter (0xfffffffc).
SAI_API_TUNNEL:_brcm_sai_vxlan_enable:1204
create a vxlan decap tunnel failed with error -5.
SAI_API_TUNNEL:brcm_sai_create_tunnel_map_entry_legacy:2723
Can't create brcm vxlan tunnel
SAI_COMMON_API_CREATE ... SAI_STATUS_FAILURE
```

CONFIG_DB/APPL_DB intent and kernel VXLAN interfaces were present, but no map entries existed in hardware and `COUNTERS_TUNNEL_NAME_MAP` was empty.

Findings from isolating the failure:

- The same failure occurs in an isolated test with a loopback source, one VLAN/VNI, no members, no peers and no advertisements.
- Adding a `dst_ip` to the tunnel is not a workaround. The SAI tunnel is still created as P2MP without `ENCAP_DST_IP`, because SONiC (`VxlanTunnel::createTunnelHw`) selects P2P only for EVPN-created dynamic destination tunnels.
- The SDK tunnel-initiator entry point rejects zero source or destination IPs. A zero destination on the source-only P2MP path is a plausible cause, but it has not been confirmed: `perf` uprobes on the SDK initiator functions captured no samples during the failure.

## Other known limitations

- **FRR ordering.** FRR 10.4.1 ignores per-VNI RD/RT commands until `advertise-all-vni` is enabled (`EVPN_ENABLED(bgp)` checks `bgp->advertise_all_vni`). The operator handles this with a local-only `SwitchEVPN` initialization step while all neighbors are shut down.
- **RT row deletion.** Deleting native RT rows caused frrcfgd to log `KeyError: 'route-target-type'`. Per-VNI withdrawal and cleanup need their own consumer-level test before production use.

## Qualification requirements

A platform can be considered qualified only after a test demonstrates all of the following:

1. Native VLAN/VNI hardware map creation succeeds, and the operator reports mapping runtime readiness, before any peer is activated.
2. Native VNI policy (RD/RT) is applied and read back exactly, without weakening verification.
3. EVPN sessions establish with negotiated EVPN capability and correct peer identity.
4. Packets are delivered between two separate access endpoints over VXLAN, and traffic is isolated between VNIs and for undeclared RTs.
5. Route withdrawal, underlay loss and recovery, AF shutdown and peer restart all behave correctly.
6. Dual-spine transit and single-spine failure work, with the test endpoints reachable through a management path that does not depend on the spines under test.
7. The full flow runs through Kubernetes controller reconciliation, not only direct agent RPCs.
8. Cleanup removes all overlay SAI objects and restores the original configuration.
