// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestRoutingShutdownPreflight(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"absent", "", true},
		{"Down", " neighbor 192.0.2.2 remote-as 65001\n neighbor 192.0.2.2 shutdown\n", true},
		{"Redis-only shutdown", " neighbor 192.0.2.2 remote-as 65001\n", false},
		{"explicit Up", " neighbor 192.0.2.2 remote-as 65001\n no neighbor 192.0.2.2 shutdown\n", false},
		{"dynamic", " bgp listen range 192.0.2.0/24 peer-group dynamic\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, c routingReadCommand) ([]byte, error) {
				if c == routingBGPDaemons {
					return []byte("frrcfgd RUNNING\nbgpd RUNNING"), nil
				}
				return []byte("router bgp 65000\n" + tc.body + "!\n"), nil
			}
			err := routingShutdownPreflight(t.Context(), run, "default", 65000, "")
			if (err == nil) != tc.want {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRoutingRelayActivationSequence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                             string
		restartErr, staleTemplate, drift bool
	}{
		{name: "dual stack restart and recovery"},
		{name: "restart failure", restartErr: true},
		{name: "stale generated config", staleTemplate: true},
		{name: "DB changed during restart", drift: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := routingDB()
			delete(db["DEVICE_METADATA|localhost"], "has_sonic_dhcpv4_relay")
			db["VLAN|Vlan100"]["dhcp_servers@"] = "192.0.2.2"
			db["DHCP_RELAY|Vlan100"] = map[string]string{"dhcpv6_servers@": "2001:db8::2"}
			desired := vlanChangeDB{"VLAN|Vlan100": {"dhcp_servers@": "192.0.2.2"}, "DHCP_RELAY|Vlan100": {"dhcpv6_servers@": "2001:db8::2"}}
			restarts, stores := 0, 0
			var receipt routingRelayReceipt
			ops := routingRelayOps{
				snapshot: func(context.Context) (vlanChangeDB, error) { return db, nil },
				restart: func(context.Context) error {
					restarts++
					if tc.restartErr {
						return fmt.Errorf("failed")
					}
					if tc.drift {
						db["PORT|Ethernet0"] = map[string]string{"mtu": "9000"}
					}
					return nil
				},
				load: func() (routingRelayReceipt, error) {
					if stores == 0 {
						return receipt, os.ErrNotExist
					}
					return receipt, nil
				},
				store: func(r routingRelayReceipt) error { stores++; receipt = r; return nil },
				wait:  func(context.Context) error { return nil },
				read: func(_ context.Context, c routingReadCommand) ([]byte, error) {
					switch c {
					case routingRelayContainer:
						return []byte(fmt.Sprintf(`[{"Id":"relay","State":{"Running":true,"StartedAt":"start-%d"}}]`, restarts)), nil
					case routingRelayGenerated:
						if tc.staleTemplate {
							return []byte("stale"), nil
						}
						return []byte("[program:dhcp6relay]\ncommand=/usr/sbin/dhcp6relay\n"), nil
					case routingRelayRendered:
						return []byte("[program:dhcp6relay]\ncommand=/usr/sbin/dhcp6relay\n"), nil
					case routingRelayProcessIdentity:
						return []byte(`[{"pid":"42","start":"100","argv":["/usr/sbin/dhcp6relay"]},{"pid":"43","start":"101","argv":["/usr/sbin/dhcrelay","-id","Vlan100","192.0.2.2"]}]`), nil
					default:
						return nil, fmt.Errorf("unexpected command %d", c)
					}
				},
			}
			err := activateRoutingRelay(t.Context(), ops, desired, "Vlan100", false, []string{"192.0.2.2"}, []string{"2001:db8::2"})
			if tc.restartErr || tc.staleTemplate || tc.drift {
				if err == nil || stores != 1 || !receipt.Pending {
					t.Fatalf("false receipt %v %d", err, stores)
				}
				return
			}
			if err != nil || restarts != 1 || stores != 2 {
				t.Fatalf("activation: %v %d %d", err, restarts, stores)
			}
			if err := activateRoutingRelay(t.Context(), ops, desired, "Vlan100", false, []string{"192.0.2.2"}, []string{"2001:db8::2"}); err != nil || restarts != 1 {
				t.Fatalf("recovery replay: %v %d", err, restarts)
			}
			verified, observed, err := routingRelayRuntime(t.Context(), ops, desired, "Vlan100", false, []string{"192.0.2.2"}, []string{"2001:db8::2"})
			if err != nil || !verified || !strings.Contains(string(observed), `"forwardingTested":false`) {
				t.Fatalf("runtime: %v %s %v", verified, observed, err)
			}
			db["DHCP_RELAY|Vlan100"]["dhcpv6_servers@"] = "2001:db8::3"
			if verified, _, _ := routingRelayRuntime(t.Context(), ops, desired, "Vlan100", false, []string{"192.0.2.2"}, []string{"2001:db8::2"}); verified {
				t.Fatal("receipt survives destination drift")
			}
		})
	}
}

func TestRoutingRestartExactArgv(t *testing.T) {
	t.Parallel()
	err := restartRoutingRelay(t.Context(), func(cmd *exec.Cmd) error {
		if !reflect.DeepEqual(cmd.Args, []string{"systemctl", "restart", "dhcp_relay.service"}) {
			t.Fatalf("argv: %v", cmd.Args)
		}
		if cmd.Stdin != nil {
			t.Fatal("unexpected stdin")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRoutingReceiptPersistence(t *testing.T) {
	t.Parallel()
	journal := t.TempDir() + "/network"
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	want := routingRelayReceipt{DBHash: "db", Container: "container/start", GeneratedHash: "config", ProcessHash: "process"}
	if _, err := routingRelayReceiptFile(journal, &want); err != nil {
		t.Fatal(err)
	}
	got, err := routingRelayReceiptFile(journal, nil)
	if err != nil || got != want {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := os.Chmod(journal+"/relay-runtime/launch.json", 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := routingRelayReceiptFile(journal, nil); err == nil {
		t.Fatal("accepted insecure receipt")
	}
}

func TestRoutingReceiptStoragePreflightPreservesEvidence(t *testing.T) {
	t.Parallel()
	journal := t.TempDir()
	if err := routingRelayPrepareStorage(journal); err != nil {
		t.Fatal(err)
	}
	want := routingRelayReceipt{DBHash: "relay-inputs", Container: "container/start", ProcessHash: "process", GeneratedHash: "config"}
	if _, err := routingRelayReceiptFile(journal, &want); err != nil {
		t.Fatal(err)
	}
	if err := routingRelayPrepareStorage(journal); err != nil {
		t.Fatal(err)
	}
	got, err := routingRelayReceiptFile(journal, nil)
	if err != nil || got != want {
		t.Fatalf("preflight overwrote launch evidence: %+v %v", got, err)
	}
	entries, err := os.ReadDir(journal + "/relay-runtime")
	if err != nil || len(entries) != 1 || entries[0].Name() != "launch.json" {
		t.Fatalf("preflight residue: %v %v", entries, err)
	}
}

func TestRoutingRelayFingerprintDependencies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, key, field, value string
		changed                 bool
	}{
		{"unrelated route", "STATIC_ROUTE|default|198.51.100.0/24", "nexthop", "192.0.2.3", false},
		{"unused VRF", "VRF|VrfOther", "NULL", "NULL", false},
		{"BGP metadata", "DEVICE_METADATA|localhost", "bgp_asn", "65000", false},
		{"relay server", "DHCP_RELAY|Vlan100", "dhcpv6_servers@", "2001:db8::3", true},
		{"SVI VRF", "VLAN_INTERFACE|Vlan100", "vrf_name", "VrfOther", true},
		{"upstream address", "INTERFACE|Ethernet0|192.0.2.1/24", "NULL", "NULL", true},
		{"relay mode", "DEVICE_METADATA|localhost", "has_sonic_dhcpv4_relay", "False", true},
		{"alias", "PORT|Ethernet0", "alias", "uplink", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := routingDB()
			before := routingRelayConfigHash(db)
			if db[tc.key] == nil {
				db[tc.key] = map[string]string{}
			}
			db[tc.key][tc.field] = tc.value
			if (routingRelayConfigHash(db) != before) != tc.changed {
				t.Fatalf("unexpected fingerprint change for %s", tc.key)
			}
		})
	}
}
