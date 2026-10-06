// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func populatedBreakoutFixture(t *testing.T) (*SonicAgent, *vlanChangeDB, *int, *int) {
	t.Helper()
	m, db, calls, saves := breakoutFixture(t)
	p, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
	for name, fields := range p.Modes["4x25G[10G]"] {
		(*db)["PORT|"+name] = maps.Clone(fields)
		(*db)["PORT|"+name]["admin_status"] = "up"
		(*db)["PORT|"+name]["mtu"] = "9100"
	}
	(*db)["PORT|Ethernet1"]["admin_status"] = "down"
	(*db)["BREAKOUT_CFG|Ethernet0"]["brkout_mode"] = "4x25G[10G]"
	(*db)["VLAN|Vlan100"] = map[string]string{"vlanid": "100"}
	(*db)["VLAN_MEMBER|Vlan100|Ethernet0"] = map[string]string{"tagging_mode": "untagged"}
	(*db)["BUFFER_POOL|ingress"] = map[string]string{"size": "100000", "type": "ingress", "mode": "dynamic"}
	(*db)["BUFFER_PROFILE|ingress"] = map[string]string{"pool": "ingress", "size": "1000", "dynamic_th": "3"}
	(*db)["BUFFER_PG|Ethernet0|3-4"] = map[string]string{"profile": "ingress"}
	(*db)["BUFFER_QUEUE|Ethernet1|0-6"] = map[string]string{"profile": "ingress"}
	return m, db, calls, saves
}

func TestBreakoutPopulatedAdoptionRecovery(t *testing.T) {
	for _, change := range []string{"none", "dependency", "admin", "MTU", "identity", "request", "adopt flag"} {
		t.Run(change, func(t *testing.T) {
			m, db, calls, saves := populatedBreakoutFixture(t)
			before := cloneBreakoutDB(*db)
			m.breakoutCAS = func(context.Context, string, vlanChangeDB, vlanChangeDB) (bool, error) {
				t.Fatal("adoption rewrote attributes")
				return false, nil
			}
			m.saveConfig = func(context.Context) *agent.Status { *saves++; return &agent.Status{Code: 500} }
			request := splitRequest()
			request.AdoptOnly = true
			got, status := m.ReconcilePortBreakout(t.Context(), request)
			if status == nil || got == nil || !got.Pending || !got.ConfigurationVerified || *saves != 1 {
				t.Fatalf("populated adoption did not reach pending save: %+v %+v saves=%d", got, status, *saves)
			}
			if *calls != 0 || !reflect.DeepEqual(before, *db) {
				t.Fatal("adoption mutated configuration")
			}
			r := *request
			switch change {
			case "dependency":
				(*db)["BUFFER_PROFILE|ingress"]["size"] = "9999"
			case "admin":
				(*db)["PORT|Ethernet1"]["admin_status"] = "up"
			case "MTU":
				(*db)["PORT|Ethernet1"]["mtu"] = "1500"
			case "identity":
				(*db)["DEVICE_METADATA|localhost"]["mac"] = "02:00:00:00:00:02"
			case "request":
				r.ChildAdminState = "up"
			case "adopt flag":
				r.AdoptOnly = false
			}
			restarted := &SonicAgent{clientPool: m.clientPool, breakoutJournalDir: m.breakoutJournalDir, resolveBreakout: m.resolveBreakout,
				breakoutSnapshot: m.breakoutSnapshot, verifyBreakoutRuntime: m.verifyBreakoutRuntime, breakoutCAS: m.breakoutCAS,
				readSavedPortConfig: func() ([]byte, error) { return portConfigJSON(t, *db), nil },
				saveConfig:          func(context.Context) *agent.Status { *saves++; return nil },
			}
			got, status = restarted.ReconcilePortBreakout(t.Context(), &r)
			if change == "none" {
				if status != nil || got.Pending || !got.PersistenceVerified || *saves != 2 {
					t.Fatalf("recovery: %+v %+v saves=%d", got, status, *saves)
				}
			} else if status == nil || !got.Pending || got.PersistenceVerified || *saves != 1 {
				t.Fatalf("foreign recovery accepted: %+v %+v", got, status)
			}
		})
	}
}

func TestBreakoutAdoptionAfterObservedAttributeChange(t *testing.T) {
	for _, name := range []string{"admin", "MTU"} {
		t.Run(name, func(t *testing.T) {
			m, db, calls, _ := populatedBreakoutFixture(t)
			if got, status := m.GetPortBreakout(t.Context(), "Ethernet0"); status != nil || !got.ConfigurationVerified {
				t.Fatalf("initial layout observation: %+v %+v", got, status)
			}
			if name == "admin" {
				(*db)["PORT|Ethernet0"]["admin_status"] = "down"
			} else {
				(*db)["PORT|Ethernet0"]["mtu"] = "1500"
			}
			before := cloneBreakoutDB(*db)
			r := splitRequest()
			r.AdoptOnly = true
			for range 2 {
				got, status := m.ReconcilePortBreakout(t.Context(), r)
				if status != nil || got.Pending || !got.PersistenceVerified {
					t.Fatalf("adoption after attribute update: %+v %+v", got, status)
				}
				if *calls != 0 || !reflect.DeepEqual(before, *db) {
					t.Fatalf("adoption changed fresh configuration; native transition calls=%d", *calls)
				}
			}
		})
	}
}

func TestBreakoutPopulatedAdoptionUnknownLayout(t *testing.T) {
	for _, name := range []string{"unknown mode", "wrong lanes", "wrong speed", "extra child"} {
		t.Run(name, func(t *testing.T) {
			m, db, calls, saves := populatedBreakoutFixture(t)
			switch name {
			case "unknown mode":
				(*db)["BREAKOUT_CFG|Ethernet0"]["brkout_mode"] = "4x20G"
			case "wrong lanes":
				(*db)["PORT|Ethernet1"]["lanes"] = "99"
			case "wrong speed":
				(*db)["PORT|Ethernet1"]["speed"] = "100000"
			case "extra child":
				(*db)["PORT|Ethernet99"] = map[string]string{"lanes": "49"}
			}
			_, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
			if status == nil || *calls != 0 || *saves != 0 {
				t.Fatal("unknown layout was adopted")
			}
		})
	}
}

func TestBreakoutSaveAcknowledgementRequiresSavedTarget(t *testing.T) {
	m, db, _, _ := breakoutFixture(t)
	before := portConfigJSON(t, *db)
	m.readSavedPortConfig = func() ([]byte, error) { return before, nil }
	got, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if status == nil || got == nil || got.PersistenceVerified || !got.Pending {
		t.Fatalf("save reply accepted stale saved layout: %+v %+v", got, status)
	}
	m.readSavedPortConfig = func() ([]byte, error) { return nil, fmt.Errorf("unreadable") }
	if got, _ := m.GetPortBreakout(t.Context(), "Ethernet0"); got != nil && got.PersistenceVerified {
		t.Fatal("unreadable saved file verified")
	}
}

func TestBreakoutAdoptOnlyCannotTransition(t *testing.T) {
	m, _, calls, saves := breakoutFixture(t)
	r := splitRequest()
	r.AdoptOnly = true
	if _, status := m.ReconcilePortBreakout(t.Context(), r); status == nil || *calls != 0 || *saves != 0 {
		t.Fatal("stale adoption dispatched a transition")
	}
}

func TestBreakoutPersistenceObservationDrift(t *testing.T) {
	m, db, _, _ := breakoutFixture(t)
	if _, status := m.ReconcilePortBreakout(t.Context(), splitRequest()); status != nil {
		t.Fatal(status)
	}
	saved := portConfigJSON(t, *db)
	m.readSavedPortConfig = func() ([]byte, error) {
		(*db)["PORT|Ethernet1"]["admin_status"] = "up"
		return saved, nil
	}
	got, status := m.GetPortBreakout(t.Context(), "Ethernet0")
	if status == nil && got.PersistenceVerified {
		t.Fatal("persistence observation ignored concurrent live drift")
	}
}
