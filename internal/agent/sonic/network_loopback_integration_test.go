//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

func TestNetworkLoopbackEnginePersistenceRecovery(t *testing.T) {
	m, db, _, saves := networkEngineFixture(t)
	m.planNetwork = nil
	options := *db.Options()
	options.DB = 0
	app := redis.NewClient(&options)
	t.Cleanup(func() { _ = app.Close() })
	m.clientPool["APPL_DB"] = app
	seed := vlanChangeDB{"LOOPBACK_INTERFACE|Loopback0": {"NULL": "NULL"}, "LOOPBACK_INTERFACE|Loopback0|10.1.0.1/32": {"NULL": "NULL"}, "PORT|Ethernet0": {"speed": "1000", "admin_status": "up"}}
	for key, fields := range seed {
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	for key, fields := range map[string]map[string]string{"INTF_TABLE:Loopback0": {"admin_status": "up"}, "INTF_TABLE:Loopback0:10.1.0.1/32": {"family": "IPv4", "scope": "global"}} {
		if err := app.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	m.linkByName = func(string) (netlink.Link, error) {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "Loopback0", Index: 5}}, nil
	}
	saved := `{}`
	kernel := `[{"ifname":"Loopback0","addr_info":[{"family":"inet","local":"10.1.0.1","prefixlen":32,"scope":"global"}]}]`
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		switch {
		case reflect.DeepEqual(cmd.Args, []string{"cat", "/etc/sonic/config_db.json"}):
			return []byte(saved), nil
		case reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "address", "show", "dev", "Loopback0"}):
			return []byte(kernel), nil
		default:
			return nil, fmt.Errorf("unexpected command %v", cmd.Args)
		}
	}))
	r := &agent.NetworkRequest{Kind: "L3Interface", OwnerID: "loopback-owner", Spec: json.RawMessage(`{"name":"Loopback0","addresses":["10.1.0.1/32"]}`)}
	got, st := m.GetNetworkResource(ctx, r)
	if st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified || *saves != 0 {
		t.Fatalf("Observe: %+v %+v", got, st)
	}
	got, st = m.EnsureNetworkResource(ctx, r)
	if st == nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("save acknowledgment without saved state must remain pending: %+v %+v", got, st)
	}
	// Simulate restart: only durable journal and native database survive.
	m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: m.clientPool, linkByName: m.linkByName, saveConfig: func(context.Context) *agent.Status { *saves++; return nil }}
	saved = `{"LOOPBACK_INTERFACE":{"Loopback0":{},"Loopback0|10.1.0.1/32":{}}}`
	kernel = `[{"ifname":"Loopback0","addr_info":[]}]`
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified {
		t.Fatalf("recovered persistence must be independent of missing kernel address: %+v %+v", got, st)
	}
	count := *saves
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || *saves != count {
		t.Fatalf("repeat must not write/save: %+v %+v", got, st)
	}
	other := *r
	other.OwnerID = "foreign"
	if _, st = m.EnsureNetworkResource(ctx, &other); st == nil {
		t.Fatal("ownership transferred")
	}
	after, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(seed, after) {
		t.Fatalf("adoption changed CONFIG_DB: %v %v", after, err)
	}
	saved = `{}`
	got, st = m.GetNetworkResource(ctx, r)
	if st != nil || got.PersistenceVerified || !got.ConfigurationVerified {
		t.Fatalf("saved drift hidden: %+v %+v", got, st)
	}
	saved = `{"LOOPBACK_INTERFACE":{"Loopback0":{"vrf_name":"VrfBlue"},"Loopback0|10.1.0.1/32":{}}}`
	got, st = m.GetNetworkResource(ctx, r)
	if st != nil || got.PersistenceVerified || !got.ConfigurationVerified {
		t.Fatalf("saved-only VRF drift hidden: %+v %+v", got, st)
	}
	got, st = m.EnsureNetworkResource(ctx, r)
	if st == nil || got.PersistenceVerified || !got.ConfigurationVerified {
		t.Fatalf("acknowledged wrong-VRF save completed: %+v %+v", got, st)
	}
}
