//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/vishvananda/netlink"
)

func evpnSequenceContext(t *testing.T, config *string) context.Context {
	t.Helper()
	return context.WithValue(evpnTestCommands(t, "", nil), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		switch strings.Join(cmd.Args[1:], " ") {
		case "exec bgp supervisorctl status":
			return []byte("frrcfgd RUNNING\nbgpd RUNNING\nzebra RUNNING"), nil
		case "exec bgp vtysh -c show running-config":
			return []byte(*config), nil
		case "exec bgp vtysh -c show bgp vrf all summary json":
			return []byte(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected routing command %v", cmd.Args)
		}
	}))
}

func TestEVPNRealRedisProductionSequence(t *testing.T) {
	m, db := evpnRedisFixture(t)
	m.planNetwork = nil // Production dispatch, planner, preflight, runtime and engine.
	if err := db.Del(t.Context(), "BGP_GLOBALS|default", "BGP_NEIGHBOR|default|192.0.2.2").Err(); err != nil {
		t.Fatal(err)
	}
	config := ""
	ctx := evpnSequenceContext(t, &config)
	bgp := evpnTestRequest("BGP", evpnCoexistBGP)
	bgp.OwnerID = "bgp-owner"
	peer := evpnTestRequest("BGPPeer", evpnCoexistBGPPeer)
	peer.OwnerID = "peer-owner"
	ensure := func(r *agent.NetworkRequest) {
		t.Helper()
		out, st := m.EnsureNetworkResource(ctx, r)
		if st != nil || out == nil || !out.PersistenceVerified {
			t.Fatalf("%s ensure: %+v %v", r.Kind, out, st)
		}
	}
	ensure(bgp)
	filters := "!\nip prefix-list " + routingExportName("default", "ipv4_unicast") + " seq 4294967295 deny 0.0.0.0/0 le 32\nipv6 prefix-list " + routingExportName("default", "ipv6_unicast") + " seq 4294967295 deny ::/0 le 128\n"
	base := "router bgp 65001\n bgp router-id 192.0.2.1\n bgp default shutdown\n no bgp default ipv4-unicast\n"
	config = base + filters
	ensure(peer) // Must create and own the neighbor through the actual BGP planner.
	unicast := " address-family ipv4 unicast\n  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.2 maximum-prefix 1000 100\n  neighbor 192.0.2.2 prefix-list " + routingExportName("default", "ipv4_unicast") + " out\n exit-address-family\n"
	config = evpnTestFRR + unicast + filters
	for _, r := range []*agent.NetworkRequest{bgp, peer} {
		out, st := m.GetNetworkResource(ctx, r)
		if st != nil || !out.RuntimeVerified {
			t.Fatalf("BGPDown runtime: %+v %v", out, st)
		}
	}
	mapping := evpnTestRequest("VLANVNI", evpnTestMap)
	ensure(mapping)
	config = evpnTestFRR + unicast + evpnTestVNI + filters
	evpn := evpnTestRequest("EVPNPeer", evpnTestPeer)
	evpn.OwnerID = "evpn-peer-owner"
	ensure(evpn)
	config = evpnTestFRR + unicast + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  no neighbor 192.0.2.2 activate\n", 1) + filters
	before, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*agent.NetworkRequest{bgp, peer, mapping, evpn} {
		out, st := m.GetNetworkResource(ctx, r)
		if st != nil || !out.ConfigurationVerified || !out.PersistenceVerified || !out.RuntimeVerified {
			t.Fatalf("%s reobserve: %+v %v", r.Kind, out, st)
		}
		ensure(r)
	}
	after, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("reobserve/reensure changed fields")
	}
	j, err := m.lockNetworkJournal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadNetworkJournal(j)
	j.close()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"BGP|default", "BGPPeer|default|192.0.2.2"} {
		for key := range state.Records[id].Fields {
			if strings.Contains(key, "EVPN") || strings.HasSuffix(key, "|l2vpn_evpn") {
				t.Fatalf("unicast owner claimed %s", key)
			}
		}
	}
	for _, r := range []*agent.NetworkRequest{evpnTestRequest("EVPNPeer", strings.Replace(evpnTestPeer, "Down", "Up", 1)), evpnTestRequest("BGPPeer", strings.Replace(evpnCoexistBGPPeer, "Down", "Up", 1))} {
		if r.Kind == "EVPNPeer" {
			r.OwnerID = evpn.OwnerID
		} else {
			r.OwnerID = peer.OwnerID
		}
		if _, st := m.EnsureNetworkResource(ctx, r); st == nil {
			t.Fatalf("%s activation bypassed guard", r.Kind)
		}
	}
	// Even exact staged CONFIG_DB cannot hide out-of-band live AF activation.
	config = strings.Replace(config, "no neighbor 192.0.2.2 activate", "neighbor 192.0.2.2 activate", 1)
	for _, r := range []*agent.NetworkRequest{bgp, peer} {
		out, st := m.GetNetworkResource(ctx, r)
		if st == nil || out.RuntimeVerified {
			t.Fatalf("%s accepted active runtime EVPN", r.Kind)
		}
	}
	// Valid disabled EVPN must not mask a unicast export leak in actual FRR.
	config = strings.Replace(config, "  neighbor 192.0.2.2 activate\n  vni", "  no neighbor 192.0.2.2 activate\n  vni", 1)
	config = strings.Replace(config, "deny 0.0.0.0/0 le 32", "permit 0.0.0.0/0 le 32", 1)
	for _, r := range []*agent.NetworkRequest{bgp, peer} {
		out, st := m.GetNetworkResource(ctx, r)
		if st != nil || out.RuntimeVerified {
			t.Fatalf("%s unicast export guard weakened by EVPN coexistence: %+v %v", r.Kind, out, st)
		}
	}
}

func evpnSVIRuntimeFixture(t *testing.T, m *SonicAgent) {
	t.Helper()
	m.clientPool["APPL_DB"] = newVLANRedis(t)
	m.linkByName = func(string) (netlink.Link, error) { return nil, lagL3MissingLinkFixture{} }
}

func TestEVPNRealRedisSVIMappingBothOrders(t *testing.T) {
	for _, first := range []string{"L3Interface", "VLANVNI"} {
		t.Run(first, func(t *testing.T) {
			m, _ := evpnRedisFixture(t)
			m.planNetwork = nil
			evpnSVIRuntimeFixture(t, m)
			ctx := evpnTestCommands(t, evpnTestFRR, nil)
			svi := evpnTestRequest("L3Interface", `{"name":"Vlan10","addresses":["203.0.113.1/24"]}`)
			mapping := evpnTestRequest("VLANVNI", evpnTestMap)
			a, b := svi, mapping
			if first == "VLANVNI" {
				a, b = mapping, svi
			}
			out, st := m.EnsureNetworkResource(ctx, a)
			if st != nil || !out.PersistenceVerified {
				t.Fatalf("first resource: %+v %v", out, st)
			}
			before, _, err := m.vlanChangeSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, st := m.EnsureNetworkResource(ctx, b); st == nil {
				t.Fatal("SVI/L2 mapping coexistence accepted")
			}
			after, _, err := m.vlanChangeSnapshot(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("conflicting second resource wrote CONFIG_DB")
			}
		})
	}
}

func TestEVPNRealRedisSVIMappingRecoveryGuard(t *testing.T) {
	for _, kind := range []string{"L3Interface", "VLANVNI"} {
		for _, phase := range []string{"pre-CAS", "post-CAS"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				m, db := evpnRedisFixture(t)
				m.planNetwork = nil
				evpnSVIRuntimeFixture(t, m)
				ctx := evpnTestCommands(t, evpnTestFRR, nil)
				r := evpnTestRequest("VLANVNI", evpnTestMap)
				if kind == "L3Interface" {
					r = evpnTestRequest("L3Interface", `{"name":"Vlan10","addresses":["203.0.113.1/24"]}`)
				}
				if phase == "pre-CAS" {
					syncs := 0
					m.journalSync = func(*os.File) error {
						syncs++
						if syncs == 2 {
							return errors.New("interrupt durable intent before CAS")
						}
						return nil
					}
				} else {
					m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "interrupt save"} }
				}
				if _, st := m.EnsureNetworkResource(ctx, r); st == nil {
					t.Fatal("expected interrupted operation")
				}
				m.journalSync = nil
				m.saveConfig = func(context.Context) *agent.Status { return nil }
				j, err := m.lockNetworkJournal(ctx)
				if err != nil {
					t.Fatal(err)
				}
				state, err := loadNetworkJournal(j)
				j.close()
				if err != nil {
					t.Fatal(err)
				}
				id, err := networkIdentity(r)
				if err != nil {
					t.Fatal(err)
				}
				if state.Records[id] == nil || state.Records[id].Pending == nil {
					t.Fatal("test failed to prepare pending recovery")
				}
				// An out-of-band conflicting resource arrives during the interruption.
				key := "VLAN_INTERFACE|Vlan10"
				row := map[string]string{"NULL": "NULL"}
				if kind == "L3Interface" {
					key = "VXLAN_TUNNEL_MAP|vtep1|map_100_Vlan10"
					row = map[string]string{"vni": "100", "vlan": "Vlan10"}
				}
				if err := db.HSet(ctx, key, row).Err(); err != nil {
					t.Fatal(err)
				}
				before, _, err := m.vlanChangeSnapshot(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, st := m.RecoverNetworkResource(ctx, r)
				if st == nil || !strings.Contains(st.Message, "pending request cannot be planned safely") {
					t.Fatalf("recovery did not revalidate L2-only invariant: %v", st)
				}
				after, _, err := m.vlanChangeSnapshot(ctx)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("unsafe recovery wrote config")
				}
			})
		}
	}
}
