//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestEVPNOperationalActivationSequence(t *testing.T) {
	m, db := evpnRedisFixture(t)
	if err := db.Del(t.Context(), "BGP_GLOBALS|default", "BGP_NEIGHBOR|default|192.0.2.2").Err(); err != nil {
		t.Fatal(err)
	}
	config := ""
	ctx := evpnSequenceContext(t, &config)
	ctx = context.WithValue(ctx, evpnCommandRunnerKey{}, evpnCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		if strings.Contains(strings.Join(cmd.Args, " "), "show bgp l2vpn evpn summary json") {
			return []byte(`{}`), nil
		}
		return evpnTestCommands(t, "", nil).Value(evpnCommandRunnerKey{}).(evpnCommandRunner)(cmd)
	}))
	ensure := func(r *agent.NetworkRequest) {
		t.Helper()
		out, st := m.EnsureNetworkResource(ctx, r)
		if st != nil || out == nil || !out.PersistenceVerified {
			t.Fatalf("%s: %+v %v", r.Kind, out, st)
		}
	}
	bgp := evpnTestRequest("BGP", evpnCoexistBGP)
	bgp.OwnerID = "bgp-owner"
	parent := evpnTestRequest("BGPPeer", evpnCoexistBGPPeer)
	parent.OwnerID = "parent-owner"
	ensure(bgp)
	filters := "!\nip prefix-list " + routingExportName("default", "ipv4_unicast") + " seq 4294967295 deny 0.0.0.0/0 le 32\nipv6 prefix-list " + routingExportName("default", "ipv6_unicast") + " seq 4294967295 deny ::/0 le 128\n"
	config = "router bgp 65001\n bgp router-id 192.0.2.1\n bgp default shutdown\n no bgp default ipv4-unicast\n" + filters
	ensure(parent)
	unicast := " address-family ipv4 unicast\n  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.2 maximum-prefix 1000 100\n  neighbor 192.0.2.2 prefix-list " + routingExportName("default", "ipv4_unicast") + " out\n exit-address-family\n"
	config = evpnTestFRR + unicast + filters
	mapping := evpnTestRequest("VLANVNI", evpnTestMap)
	mapping.OwnerID = "mapping-owner"
	ensure(mapping)
	config = evpnTestFRR + unicast + evpnTestVNI + filters
	var ms evpnMapSpec
	if err := json.Unmarshal(mapping.Spec, &ms); err != nil {
		t.Fatal(err)
	}
	ref := agent.EVPNMappingSnapshot{Name: "mapping", UID: mapping.OwnerID, Generation: 1, Tunnel: ms.Tunnel, VLANID: ms.VLANID, VNI: ms.VNI, RouteDistinguisher: ms.RouteDistinguisher, ImportRouteTargets: ms.ImportRouteTargets, ExportRouteTargets: ms.ExportRouteTargets}
	var spec map[string]any
	if err := json.Unmarshal([]byte(evpnTestPeer), &spec); err != nil {
		t.Fatal(err)
	}
	spec["mappingRefs"] = []map[string]string{{"name": "mapping"}}
	spec["mappings"] = []agent.EVPNMappingSnapshot{ref}
	request := func(kind, owner string, fields any) *agent.NetworkRequest {
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return &agent.NetworkRequest{Kind: kind, OwnerID: owner, Spec: raw}
	}
	peer := request("EVPNPeer", "evpn-owner", spec)
	m.saveConfig = func(context.Context) *agent.Status {
		return &agent.Status{Code: 500, Message: "interrupted policy save"}
	}
	if _, st := m.EnsureNetworkResource(ctx, peer); st == nil {
		t.Fatal("save failure lost")
	}
	m.saveConfig = func(context.Context) *agent.Status { return nil }
	if out, st := m.RecoverNetworkResource(ctx, peer); st != nil || !out.PersistenceVerified {
		t.Fatalf("policy recovery: %+v %v", out, st)
	}
	p, err := evpnBuildPeerPolicy(peer.OwnerID, "192.0.2.2", ms.ImportRouteTargets, ms.ExportRouteTargets)
	if err != nil {
		t.Fatal(err)
	}
	policy := ""
	for _, direction := range []struct {
		name    string
		targets []string
	}{{p.In, p.Import}, {p.Out, p.Export}} {
		for _, rt := range direction.targets {
			policy += "bgp extcommunity-list standard " + direction.name + " permit rt " + rt + "\n"
		}
		policy += "route-map " + direction.name + " permit 10\n match extcommunity " + direction.name + "\n!\nroute-map " + direction.name + " deny 65535\n!\n"
	}
	af := "  neighbor 192.0.2.2 route-map " + p.In + " in\n  neighbor 192.0.2.2 route-map " + p.Out + " out\n  neighbor 192.0.2.2 send-community extended\n"
	config = evpnTestFRR + unicast + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n"+af, 1) + filters + policy
	globalSpec := map[string]any{"tunnel": "vtep1", "adminState": "Up", "mappingRefs": spec["mappingRefs"], "mappings": spec["mappings"]}
	ensure(request("EVPN", "global-owner", globalSpec))
	af += "  advertise-all-vni\n"
	config = evpnTestFRR + unicast + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n"+af, 1) + filters + policy
	spec["adminState"] = "Up"
	peer = request("EVPNPeer", peer.OwnerID, spec)
	ensure(peer)
	af += "  neighbor 192.0.2.2 activate\n"
	config = evpnTestFRR + unicast + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n"+af, 1) + filters + policy
	parent.Spec = []byte(strings.Replace(evpnCoexistBGPPeer, "Down", "Up", 1))
	ensure(parent)
	config = strings.ReplaceAll(config, " neighbor 192.0.2.2 shutdown\n", "")
	for _, r := range []*agent.NetworkRequest{bgp, parent, mapping, peer, request("EVPN", "global-owner", globalSpec)} {
		ensure(r)
	}
	// AF withdrawal must not depend on shutting down the shared parent first.
	spec["adminState"] = "Down"
	peer = request("EVPNPeer", peer.OwnerID, spec)
	ensure(peer)
	config = strings.Replace(config, "  neighbor 192.0.2.2 activate\n  vni", "  vni", 1)
	globalSpec["adminState"] = "Down"
	ensure(request("EVPN", "global-owner", globalSpec))
}
