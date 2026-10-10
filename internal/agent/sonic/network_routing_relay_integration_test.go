//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func routingEngine(t *testing.T) (*SonicAgent, *redis.Client) {
	t.Helper()
	m, db, _, _ := networkEngineFixture(t)
	m.planNetwork = nil // Exercise production dispatch, planners and callbacks.
	for key, fields := range routingDB() {
		if len(fields) == 0 {
			fields = map[string]string{"NULL": "NULL"}
		}
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	return m, db
}

func TestRoutingRealEnginePeerStaging(t *testing.T) {
	m, db := routingEngine(t)
	config := ""
	runner := routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		args := strings.Join(cmd.Args[1:], " ")
		switch args {
		case "exec bgp supervisorctl status":
			return []byte("frrcfgd RUNNING\nbgpd RUNNING"), nil
		case "exec bgp vtysh -c show running-config":
			return []byte(config), nil
		case "exec bgp vtysh -c show bgp vrf all summary json":
			return []byte(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected command: %s", args)
		}
	})
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, runner)
	bgp := routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`)
	if _, st := m.EnsureNetworkResource(ctx, bgp); st != nil {
		t.Fatal(st)
	}
	base := "router bgp 65000\n bgp router-id 192.0.2.1\n no bgp default ipv4-unicast\n"
	filters := "!\nip prefix-list " + routingExportName("default", "ipv4_unicast") + " seq 4294967295 deny 0.0.0.0/0 le 32\nipv6 prefix-list " + routingExportName("default", "ipv6_unicast") + " seq 4294967295 deny ::/0 le 128\n"
	config = base + filters
	peer := routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast","ipv6Unicast"]}`)
	if out, st := m.EnsureNetworkResource(ctx, peer); st != nil || !out.ConfigurationVerified {
		t.Fatalf("Down staging: %+v %v", out, st)
	}
	peer.Spec = json.RawMessage(`{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast","ipv6Unicast"],"adminState":"Up"}`)
	if _, st := m.EnsureNetworkResource(ctx, peer); st == nil {
		t.Fatal("enabled before FRR consumed staged policy")
	}
	if db.HGet(ctx, "BGP_NEIGHBOR|default|192.0.2.2", "admin_status").Val() != "down" {
		t.Fatal("preflight failure wrote admin Up")
	}
	staged := base + " neighbor 192.0.2.2 remote-as 65001\n neighbor 192.0.2.2 shutdown\n"
	for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
		staged += " address-family " + strings.ReplaceAll(af, "_", " ") + "\n  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.2 maximum-prefix 1000 100\n  neighbor 192.0.2.2 prefix-list " + routingExportName("default", af) + " out\n exit-address-family\n"
	}
	config = staged + filters
	if _, st := m.EnsureNetworkResource(ctx, peer); st != nil {
		t.Fatal(st)
	}
	if db.HGet(ctx, "BGP_NEIGHBOR|default|192.0.2.2", "admin_status").Val() != "up" {
		t.Fatal("owned peer not activated")
	}
	config = strings.ReplaceAll(config, " neighbor 192.0.2.2 shutdown\n", "")
	if out, st := m.GetNetworkResource(ctx, peer); st != nil || !out.RuntimeVerified {
		t.Fatalf("Up runtime: %+v %v", out, st)
	}
	// Redis can say Down before FRR catches up. Global policy must still wait.
	peer.Spec = json.RawMessage(`{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast","ipv6Unicast"],"adminState":"Down"}`)
	if _, st := m.EnsureNetworkResource(ctx, peer); st != nil {
		t.Fatal(st)
	}
	bgp.Spec = json.RawMessage(`{"localASN":65000,"routerID":"192.0.2.1","prefixes":["192.0.2.0/24"]}`)
	if _, st := m.EnsureNetworkResource(ctx, bgp); st == nil {
		t.Fatal("policy write trusted Redis-only shutdown")
	}
	if db.Exists(ctx, "BGP_GLOBALS_AF_NETWORK|default|ipv4_unicast|192.0.2.0/24").Val() != 0 {
		t.Fatal("unsafe network written")
	}
}

func TestRoutingRealEngineRelayRecovery(t *testing.T) {
	for _, family := range []string{"legacy-v4", "v6", "dual"} {
		t.Run(family, func(t *testing.T) {
			m, db := routingEngine(t)
			if err := db.HDel(t.Context(), "DEVICE_METADATA|localhost", "has_sonic_dhcpv4_relay").Err(); err != nil {
				t.Fatal(err)
			}
			restarts := 0
			uncertain := true
			launchedV4 := "192.0.2.2"
			runner := routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				args := strings.Join(cmd.Args[1:], " ")
				if cmd.Args[0] == "systemctl" {
					if args != "restart dhcp_relay.service" {
						t.Fatalf("unexpected mutation %v", cmd.Args)
					}
					restarts++
					if v := db.HGet(t.Context(), "VLAN|Vlan100", "dhcp_servers@").Val(); v != "" {
						launchedV4 = v
					}
					if uncertain {
						return nil, fmt.Errorf("restart completed but response lost")
					}
					return nil, nil
				}
				switch {
				case strings.HasPrefix(args, "inspect "):
					return []byte(fmt.Sprintf(`[{"Id":"relay","State":{"Running":true,"StartedAt":"launch-%d"}}]`, restarts)), nil
				case strings.Contains(args, " cat "), strings.Contains(args, " sonic-cfggen "):
					return []byte("[program:dhcp6relay]\ncommand=/usr/sbin/dhcp6relay\n"), nil
				case strings.Contains(args, " python3 "):
					if restarts == 0 {
						return []byte(`[]`), nil
					}
					return []byte(fmt.Sprintf(`[{"pid":"10","start":"100","argv":["/usr/sbin/dhcp6relay"]},{"pid":"11","start":"101","argv":["/usr/sbin/dhcrelay","-id","Vlan100",%q]}]`, launchedV4)), nil
				case strings.Contains(args, " ps "):
					if restarts == 0 {
						return nil, nil
					}
					return []byte("/usr/sbin/dhcrelay -id Vlan100 " + launchedV4 + "\n/usr/sbin/dhcp6relay"), nil
				default:
					return nil, fmt.Errorf("unexpected command: %v", cmd.Args)
				}
			})
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, runner)
			spec := `{"vlanID":100,"ipv4Servers":["192.0.2.2"],"ipv6Servers":["2001:db8::2"]}`
			if family == "legacy-v4" {
				spec = `{"vlanID":100,"ipv4Servers":["192.0.2.2"]}`
			}
			if family == "v6" {
				spec = `{"vlanID":100,"ipv6Servers":["2001:db8::2"]}`
			}
			req := routingRequest("DHCPRelay", spec)
			if _, st := m.GetNetworkResource(ctx, req); st != nil {
				t.Fatal(st)
			}
			if restarts != 0 {
				t.Fatal("Get restarted service")
			}
			if out, st := m.EnsureNetworkResource(ctx, req); st == nil || !out.ConfigurationVerified || out.PersistenceVerified || restarts != 1 {
				t.Fatalf("uncertain restart: %+v %v count=%d", out, st, restarts)
			}
			// Fresh agent, real journal + receipt, no fake planner and no re-dispatch.
			m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { return nil }}
			if out, st := m.EnsureNetworkResource(ctx, req); st != nil || !out.RuntimeVerified || !out.PersistenceVerified || restarts != 1 {
				t.Fatalf("recovery: %+v %v count=%d", out, st, restarts)
			}
			uncertain = false
			req.Spec = json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(spec, "192.0.2.2", "192.0.2.3"), "2001:db8::2", "2001:db8::3"))
			if out, st := m.EnsureNetworkResource(ctx, req); st != nil || !out.RuntimeVerified || !out.PersistenceVerified || restarts != 2 {
				t.Fatalf("owned destination update: %+v %v count=%d", out, st, restarts)
			}
			if _, st := m.EnsureNetworkResource(ctx, req); st != nil || restarts != 2 {
				t.Fatalf("no-op restart: %v count=%d", st, restarts)
			}
			// A separate real network operation refreshes persistence but must not
			// invalidate a relay launch merely because the full DB hash changed.
			other := routingRequest("VRF", `{"name":"VrfUnrelated"}`)
			_, _ = m.EnsureNetworkResource(ctx, other) // Runtime netlink may be unavailable on the test host.
			if db.Exists(ctx, "VRF|VrfUnrelated").Val() != 1 {
				t.Fatal("unrelated VRF was not configured")
			}
			if out, st := m.GetNetworkResource(ctx, req); st != nil || !out.RuntimeVerified {
				t.Fatalf("unrelated VRF invalidated relay readiness: %+v %v", out, st)
			}
			if out, st := m.EnsureNetworkResource(ctx, req); st != nil || !out.RuntimeVerified || restarts != 2 {
				t.Fatalf("unrelated VRF forced restart: %+v %v count=%d", out, st, restarts)
			}
		})
	}
}

func TestRoutingRealEngineReceiptStoragePreflight(t *testing.T) {
	for _, mode := range []string{"file", "readonly", "symlink", "malformed-receipt"} {
		t.Run(mode, func(t *testing.T) {
			m, db := routingEngine(t)
			dir := filepath.Join(m.networkJournalDir, "relay-runtime")
			switch mode {
			case "file":
				if err := os.WriteFile(dir, []byte("wrong type"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if mode == "readonly" {
					if err := os.Chmod(dir, 0500); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
				}
				if mode == "malformed-receipt" {
					if err := os.WriteFile(filepath.Join(dir, "launch.json"), []byte("not JSON"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			commands := 0
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) { commands++; return nil, fmt.Errorf("no commands expected") }))
			if _, st := m.EnsureNetworkResource(ctx, routingRequest("DHCPRelay", `{"vlanID":100,"ipv6Servers":["2001:db8::2"]}`)); st == nil {
				t.Fatal("invalid storage accepted")
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if vlanAuthorityHash(before) != vlanAuthorityHash(after) {
				t.Fatal("storage failure mutated DB")
			}
			if db.Exists(t.Context(), "DHCP_RELAY|Vlan100").Val() != 0 {
				t.Fatal("relay created before storage validation")
			}
			if _, err := os.Stat(filepath.Join(m.networkJournalDir, "network.json")); !os.IsNotExist(err) {
				t.Fatalf("storage failure created pending journal: %v", err)
			}
			if commands != 0 {
				t.Fatalf("storage failure dispatched %d commands", commands)
			}
		})
	}
}
