// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"strings"
	"testing"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func TestVLANInvalidRequests(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		vlan *agent.VLAN
	}{
		{name: "nil"},
		{name: "zero", vlan: &agent.VLAN{}},
		{name: "reserved", vlan: &agent.VLAN{ID: 4095}},
		{name: "overflow", vlan: &agent.VLAN{ID: ^uint32(0)}},
		{name: "empty name", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{TaggingMode: "tagged"}}}},
		{name: "alias", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "eth0-0", TaggingMode: "tagged"}}}},
		{name: "leading zero", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet00", TaggingMode: "tagged"}}}},
		{name: "negative", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet-1", TaggingMode: "tagged"}}}},
		{name: "subinterface", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0.1", TaggingMode: "tagged"}}}},
		{name: "glob", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet*", TaggingMode: "tagged"}}}},
		{name: "LAG", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "PortChannel1", TaggingMode: "tagged"}}}},
		{name: "empty mode", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0"}}}},
		{name: "uppercase mode", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "TAGGED"}}}},
		{name: "duplicate", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}, {InterfaceName: "Ethernet0", TaggingMode: "tagged"}}}},
		{name: "conflicting duplicate", vlan: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}, {InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			got, status := m.EnsureVLAN(t.Context(), tc.vlan)
			if got != nil || status == nil || status.Code != agenterrors.BAD_REQUEST {
				t.Fatalf("got=%+v status=%v, want BAD_REQUEST", got, status)
			}
			if *saves != 0 || len(dbs["CONFIG_DB"].writes) != 0 || m.configDirty {
				t.Fatal("invalid request changed configuration or persistence state")
			}
		})
	}
	for _, id := range []uint32{0, 4095, ^uint32(0)} {
		m, _, saves := newTestAgent(t)
		got, status := m.GetVLAN(t.Context(), id)
		if got != nil || status == nil || status.Code != agenterrors.BAD_REQUEST || *saves != 0 {
			t.Fatalf("GetVLAN(%d): got=%+v status=%v saves=%d", id, got, status, *saves)
		}
	}
}

func TestVLANApplyDisablesAutomaticRedisReplay(t *testing.T) {
	t.Parallel()
	m, dbs, _ := newTestAgent(t)
	var evaluated bool
	dbs["CONFIG_DB"].before = func(_ context.Context, cmd redis.Cmder) {
		if cmd.Name() == "eval" {
			evaluated = true
			if !cmd.NoRetry() {
				t.Error("VLAN EVAL must not be replayed after an ambiguous transport failure")
			}
		}
	}
	_, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100})
	if !evaluated || status == nil || !m.configDirty {
		t.Fatalf("evaluated=%v status=%v dirty=%v", evaluated, status, m.configDirty)
	}
}

func TestVLANReadFailureIsNotAbsence(t *testing.T) {
	t.Parallel()
	m, dbs, saves := newTestAgent(t)
	dbs["CONFIG_DB"].fail["eval"] = fmt.Errorf("read unavailable")
	got, status := m.GetVLAN(t.Context(), 100)
	if got != nil || status == nil || status.Code == agenterrors.NOT_FOUND || !strings.Contains(status.Message, "read unavailable") {
		t.Fatalf("got=%+v status=%v", got, status)
	}
	if m.configDirty || *saves != 0 || len(dbs["CONFIG_DB"].writes) != 0 {
		t.Fatal("read failure changed persistence or configuration")
	}
}

func TestVLANCanceledRequestDoesNotDispatch(t *testing.T) {
	t.Parallel()
	m, dbs, saves := newTestAgent(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dbs["CONFIG_DB"].before = func(context.Context, redis.Cmder) { t.Error("canceled request dispatched to Redis") }
	_, getStatus := m.GetVLAN(ctx, 100)
	_, ensureStatus := m.EnsureVLAN(ctx, &agent.VLAN{ID: 100})
	if getStatus == nil || ensureStatus == nil || m.configDirty || *saves != 0 {
		t.Fatalf("get=%v ensure=%v dirty=%v saves=%d", getStatus, ensureStatus, m.configDirty, *saves)
	}
}
