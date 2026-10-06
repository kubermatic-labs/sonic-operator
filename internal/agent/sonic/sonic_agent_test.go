// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"maps"
	"net"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

// Intercept commands before go-redis opens a connection. Unexpected commands fail
// rather than accidentally reaching a real Redis instance.
type redisFixture struct {
	hashes map[string]map[string]string
	writes []string
	fail   map[string]error
	before func(context.Context, redis.Cmder)
}

func (f *redisFixture) DialHook(_ redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("unexpected Redis connection")
	}
}

func (f *redisFixture) ProcessPipelineHook(_ redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(context.Context, []redis.Cmder) error {
		return fmt.Errorf("unexpected Redis pipeline")
	}
}

func (f *redisFixture) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if f.before != nil {
			f.before(ctx, cmd)
		}
		if err := ctx.Err(); err != nil {
			cmd.SetErr(err)
			return err
		}
		if err := f.fail[cmd.Name()]; err != nil {
			cmd.SetErr(err)
			return err
		}
		args := cmd.Args()
		var key string
		if len(args) > 1 {
			key = fmt.Sprint(args[1])
		}
		switch cmd.Name() {
		case "ping":
			cmd.(*redis.StatusCmd).SetVal("PONG")
		case "keys":
			var keys []string
			for k := range f.hashes {
				if match, _ := path.Match(key, k); match {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			cmd.(*redis.StringSliceCmd).SetVal(keys)
		case "exists":
			if len(f.hashes[key]) > 0 {
				cmd.(*redis.IntCmd).SetVal(1)
			}
		case "hgetall":
			cmd.(*redis.MapStringStringCmd).SetVal(maps.Clone(f.hashes[key]))
		case "hget":
			value, ok := f.hashes[key][fmt.Sprint(args[2])]
			if !ok {
				cmd.SetErr(redis.Nil)
				return redis.Nil
			}
			cmd.(*redis.StringCmd).SetVal(value)
		case "hset":
			f.writes = append(f.writes, fmt.Sprint(args))
			if f.hashes[key] == nil {
				f.hashes[key] = map[string]string{}
			}
			for i := 2; i < len(args); i += 2 {
				f.hashes[key][fmt.Sprint(args[i])] = fmt.Sprint(args[i+1])
			}
			cmd.(*redis.IntCmd).SetVal(1)
		case "hdel":
			f.writes = append(f.writes, fmt.Sprint(args))
			delete(f.hashes[key], fmt.Sprint(args[2]))
			cmd.(*redis.IntCmd).SetVal(1)
		default:
			err := fmt.Errorf("unexpected Redis command %s", cmd.Name())
			cmd.SetErr(err)
			return err
		}
		return nil
	}
}

func newTestAgent(t *testing.T) (*SonicAgent, map[string]*redisFixture, *int) {
	t.Helper()
	m := &SonicAgent{clientPool: map[string]*redis.Client{}}
	dbs := map[string]*redisFixture{}
	for _, name := range []string{"CONFIG_DB", "STATE_DB", "APPL_DB"} {
		fixture := &redisFixture{hashes: map[string]map[string]string{}, fail: map[string]error{}}
		client := redis.NewClient(&redis.Options{MaxRetries: -1})
		client.AddHook(fixture)
		t.Cleanup(func() { _ = client.Close() })
		m.clientPool[name] = client
		dbs[name] = fixture
	}
	saves := 0
	m.saveConfig = func(context.Context) *agent.Status { saves++; return nil }
	m.readSavedPortConfig = func() ([]byte, error) { return portConfigJSON(t, dbs["CONFIG_DB"].hashes), nil }
	m.linkByName = func(name string) (netlink.Link, error) {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name: name, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1},
		}}, nil
	}
	m.versionInfo = func() (map[string]string, error) { return nil, fmt.Errorf("no version file") }
	return m, dbs, &saves
}

func TestInterfaceStatusSources(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, configured, state, oper string
		wantAdmin, wantOper           agent.DeviceStatus
	}{
		{"configured up, link down", "up", "down", "down", agent.StatusUp, agent.StatusDown},
		{"configured down, link up", "down", "up", "up", agent.StatusDown, agent.StatusUp},
		{"missing admin", "", "up", "up", agent.StatusUnknown, agent.StatusUp},
		{"invalid admin", "invalid", "up", "down", agent.StatusUnknown, agent.StatusDown},
		{"unknown operation", "up", "down", "", agent.StatusUp, agent.StatusUnknown},
		{"invalid operation", "up", "down", "invalid", agent.StatusUp, agent.StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			fields := map[string]string{"alias": "Ethernet1/1"}
			if tc.configured != "" {
				fields["admin_status"] = tc.configured
			}
			dbs["CONFIG_DB"].hashes["PORT|Ethernet0"] = fields
			dbs["STATE_DB"].hashes["PORT_TABLE|Ethernet0"] = map[string]string{"admin_status": tc.state}
			dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet0"] = map[string]string{"oper_status": tc.oper}
			got, status := m.GetInterface(t.Context(), &agent.Interface{Name: "eth0-0"})
			if status != nil {
				t.Fatalf("GetInterface: %v", status)
			}
			list, status := m.ListInterfaces(t.Context())
			if status != nil || list == nil || len(list.Items) != 1 {
				t.Fatalf("ListInterfaces: list=%+v status=%v", list, status)
			}
			for _, iface := range []agent.Interface{*got, list.Items[0]} {
				if iface.AdminStatus != tc.wantAdmin || iface.OperationStatus != tc.wantOper {
					t.Errorf("statuses=(%q, %q), want (%q, %q)", iface.AdminStatus, iface.OperationStatus, tc.wantAdmin, tc.wantOper)
				}
				if iface.AliasName != fields["alias"] || iface.NativeName != "Ethernet0" || iface.Name != "eth0-0" {
					t.Errorf("interface identity changed: %+v", iface)
				}
			}
			if len(dbs["CONFIG_DB"].writes) != 0 || *saves != 0 {
				t.Fatal("reads must not mutate config")
			}
		})
	}
}

func TestSetInterfaceValidationAndNoOp(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		alias  bool
		fields map[string]string
		input  agent.Interface
		code   uint32
	}{
		{name: "admin missing port", input: agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp}, code: agenterrors.NOT_FOUND},
		{name: "alias missing port", alias: true, input: agent.Interface{Name: "Ethernet0", AliasName: "new"}, code: agenterrors.NOT_FOUND},
		{name: "unknown admin", fields: map[string]string{"admin_status": "up"}, input: agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUnknown}, code: agenterrors.BAD_REQUEST},
		{name: "invalid admin", fields: map[string]string{"admin_status": "up"}, input: agent.Interface{Name: "Ethernet0", AdminStatus: "UP"}, code: agenterrors.BAD_REQUEST},
		{name: "empty admin", fields: map[string]string{"admin_status": "up"}, input: agent.Interface{Name: "Ethernet0"}, code: agenterrors.BAD_REQUEST},
		{name: "admin no-op preserves alias", fields: map[string]string{"admin_status": "up", "alias": "existing"}, input: agent.Interface{Name: "eth0-0", AdminStatus: agent.StatusUp, AliasName: "ignored"}},
		{name: "alias no-op", alias: true, fields: map[string]string{"admin_status": "down", "alias": "existing"}, input: agent.Interface{Name: "eth0-0", AliasName: "existing"}},
		{name: "absent alias no-op", alias: true, fields: map[string]string{"admin_status": "up"}, input: agent.Interface{Name: "Ethernet0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			config := dbs["CONFIG_DB"]
			if tc.fields != nil {
				config.hashes["PORT|Ethernet0"] = maps.Clone(tc.fields)
			}
			var got *agent.Interface
			var status *agent.Status
			if tc.alias {
				got, status = m.SetInterfaceAliasName(t.Context(), &tc.input)
			} else {
				got, status = m.SetInterfaceAdminStatus(t.Context(), &tc.input)
			}
			if tc.code != 0 {
				if status == nil || status.Code != tc.code {
					t.Errorf("status=%v, want code=%d", status, tc.code)
				}
			} else if status != nil || got == nil {
				t.Errorf("no-op: got=%+v status=%v", got, status)
			} else if got.AliasName != tc.fields["alias"] || got.AdminStatus != agent.DeviceStatus(tc.fields["admin_status"]) {
				t.Errorf("no-op response does not reflect stored config: %+v", got)
			}
			if len(config.writes) != 0 || *saves != 0 {
				t.Errorf("unexpected mutation: writes=%v saves=%d", config.writes, *saves)
			}
			if !reflect.DeepEqual(config.hashes["PORT|Ethernet0"], tc.fields) {
				t.Errorf("config changed: %+v", config.hashes)
			}
		})
	}
}

func TestSetInterfaceChanges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, field, oldValue, desired string
		alias, saveFails, fieldMissing bool
	}{
		{name: "admin down", field: "admin_status", oldValue: "up", desired: "down"},
		{name: "alias change", field: "alias", oldValue: "existing", desired: "new", alias: true},
		{name: "explicit empty alias", field: "alias", oldValue: "existing", alias: true},
		{name: "rollback admin", field: "admin_status", oldValue: "up", desired: "down", saveFails: true},
		{name: "rollback alias", field: "alias", oldValue: "existing", desired: "new", alias: true, saveFails: true},
		{name: "rollback absent admin", field: "admin_status", desired: "up", saveFails: true, fieldMissing: true},
		{name: "rollback absent alias", field: "alias", desired: "new", alias: true, saveFails: true, fieldMissing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			config := dbs["CONFIG_DB"]
			fields := map[string]string{"admin_status": "up", "alias": "existing", "index": "1"}
			fields[tc.field] = tc.oldValue
			if tc.fieldMissing {
				delete(fields, tc.field)
			}
			before := maps.Clone(fields)
			config.hashes["PORT|Ethernet0"] = fields
			dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet0"] = map[string]string{"oper_status": "up"}
			if tc.saveFails {
				m.saveConfig = func(context.Context) *agent.Status {
					(*saves)++
					return agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "save failed")
				}
			}
			input := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.DeviceStatus(tc.desired), AliasName: "ignored"}
			var got *agent.Interface
			var status *agent.Status
			if tc.alias {
				input.AliasName = tc.desired
				got, status = m.SetInterfaceAliasName(t.Context(), input)
			} else {
				got, status = m.SetInterfaceAdminStatus(t.Context(), input)
			}
			if *saves != 1 {
				t.Errorf("saves=%d, want 1", *saves)
			}
			if tc.saveFails {
				if status == nil || !reflect.DeepEqual(fields, before) {
					t.Errorf("rollback: status=%v fields=%v want=%v", status, fields, before)
				}
				return
			}
			before[tc.field] = tc.desired
			if status != nil || got == nil || !reflect.DeepEqual(fields, before) || len(config.writes) != 1 {
				t.Fatalf("change: got=%+v status=%v fields=%v writes=%v", got, status, fields, config.writes)
			}
			if got.AliasName != before["alias"] || got.AdminStatus != agent.DeviceStatus(before["admin_status"]) {
				t.Errorf("response does not reflect config: %+v", got)
			}
		})
	}
}

func TestGetDeviceInfoVersionFallback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, redisVersion, yamlVersion, buildVersion, want string
	}{
		{"build version", "", "", "202505.1", "202505.1"},
		{"legacy yaml version", "", "legacy", "build", "legacy"},
		{"redis wins", "redis", "yaml", "build", "redis"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, _ := newTestAgent(t)
			dbs["CONFIG_DB"].hashes["DEVICE_METADATA|localhost"] = map[string]string{
				"mac": "02:00:00:00:00:01", "sonic_os_version": tc.redisVersion,
			}
			m.versionInfo = func() (map[string]string, error) {
				return map[string]string{"sonic_os_version": tc.yamlVersion, "build_version": tc.buildVersion, "hwsku": "sku", "asic_type": "asic"}, nil
			}
			got, status := m.GetDeviceInfo(t.Context())
			if status != nil || got == nil || got.SonicOSVersion != tc.want || got.Hwsku != "sku" || got.AsicType != "asic" {
				t.Fatalf("device=%+v status=%v, want version=%q", got, status, tc.want)
			}
		})
	}
}

func TestListPortsIndexInventory(t *testing.T) {
	t.Parallel()
	m, dbs, _ := newTestAgent(t)
	config := dbs["CONFIG_DB"]
	add := func(n, index int) {
		name := fmt.Sprintf("Ethernet%d", n)
		config.hashes["PORT|"+name] = map[string]string{"index": fmt.Sprint(index), "alias": fmt.Sprintf("port%d", index)}
		dbs["APPL_DB"].hashes["PORT_TABLE:"+name] = map[string]string{"oper_status": "up"}
	}
	for n := range 4 {
		add(n, 1)
	}
	for n := 4; n <= 124; n += 4 {
		add(n, n/4+1)
	}
	add(129, 33)
	add(131, 34)
	if len(config.hashes) != 37 {
		t.Fatalf("fixture has %d logical interfaces, want 37", len(config.hashes))
	}
	got, status := m.ListPorts(t.Context())
	if status != nil || got == nil || len(got.Items) != 34 {
		t.Fatalf("ports=%+v status=%v, want 34 physical parents", got, status)
	}
	seen := map[string]bool{}
	for _, port := range got.Items {
		if seen[port.Name] || config.hashes["PORT|"+port.Name] == nil {
			t.Errorf("duplicate or fabricated port: %+v", port)
		}
		seen[port.Name] = true
		if port.Alias != config.hashes["PORT|"+port.Name]["alias"] {
			t.Errorf("incorrect alias: %+v", port)
		}
	}
	for _, name := range []string{"Ethernet0", "Ethernet129", "Ethernet131"} {
		if !seen[name] {
			t.Errorf("missing parent %s", name)
		}
	}
	for _, name := range []string{"Ethernet1", "Ethernet2", "Ethernet3", "Ethernet128"} {
		if seen[name] {
			t.Errorf("fabricated or duplicate parent %s", name)
		}
	}
}

func TestListPortsLegacyAndConservativeFallback(t *testing.T) {
	t.Parallel()
	m, dbs, _ := newTestAgent(t)
	dbs["CONFIG_DB"].hashes = map[string]map[string]string{
		"PORT|Ethernet0":    {"index": "1", "alias": "configured"},
		"PORT|Ethernet1":    {"index": "1"},
		"PORT|Ethernet8":    {"index": "invalid"},
		"PORT|Ethernet9":    {"index": ""},
		"PORT|Ethernet10.1": {"index": "4"},
		"PORT|PortChannel1": {"index": "5"},
	}
	dbs["APPL_DB"].hashes = map[string]map[string]string{
		"PORT_TABLE:Ethernet0":  {"parent_port": "Ethernet0", "alias": "stale"},
		"PORT_TABLE:Ethernet1":  {"parent_port": "Ethernet1"},
		"PORT_TABLE:Ethernet4":  {"parent_port": "Ethernet4", "alias": "legacy"},
		"PORT_TABLE:Ethernet5":  {"parent_port": "Ethernet4"},
		"PORT_TABLE:Ethernet12": {"parent_port": "Ethernet12"},
	}
	got, status := m.ListPorts(t.Context())
	if status != nil || got == nil {
		t.Fatalf("ListPorts: %v", status)
	}
	want := map[string]string{"Ethernet0": "configured", "Ethernet4": "legacy", "Ethernet12": "Ethernet12"}
	actual := map[string]string{}
	for _, port := range got.Items {
		actual[port.Name] = port.Alias
	}
	if !reflect.DeepEqual(actual, want) || len(got.Items) != len(want) {
		t.Errorf("ports=%v, want=%v", got.Items, want)
	}
}

func TestSetInterfaceReadFailureDoesNotWrite(t *testing.T) {
	t.Parallel()
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprintf("alias=%v", alias), func(t *testing.T) {
			m, dbs, saves := newTestAgent(t)
			dbs["CONFIG_DB"].fail["hgetall"] = fmt.Errorf("read failed")
			input := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp, AliasName: "new"}
			var status *agent.Status
			if alias {
				_, status = m.SetInterfaceAliasName(t.Context(), input)
			} else {
				_, status = m.SetInterfaceAdminStatus(t.Context(), input)
			}
			if status == nil || !strings.Contains(status.Message, "read failed") || *saves != 0 || len(dbs["CONFIG_DB"].writes) != 0 {
				t.Fatalf("status=%v saves=%d writes=%v", status, *saves, dbs["CONFIG_DB"].writes)
			}
		})
	}
}

func TestSetInterfaceWriteFailureDoesNotSave(t *testing.T) {
	t.Parallel()
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprintf("alias=%v", alias), func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			fields := map[string]string{"admin_status": "down", "alias": "existing"}
			dbs["CONFIG_DB"].hashes["PORT|Ethernet0"] = fields
			dbs["CONFIG_DB"].fail["hset"] = fmt.Errorf("write failed")
			input := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp, AliasName: "new"}
			var status *agent.Status
			if alias {
				_, status = m.SetInterfaceAliasName(t.Context(), input)
			} else {
				_, status = m.SetInterfaceAdminStatus(t.Context(), input)
			}
			if status == nil || status.Code != agenterrors.REDIS_HSET_FAIL || *saves != 0 {
				t.Fatalf("status=%v saves=%d", status, *saves)
			}
			if fields["admin_status"] != "down" || fields["alias"] != "existing" {
				t.Fatalf("config changed: %v", fields)
			}
		})
	}
}

func TestInterfaceWithoutAlias(t *testing.T) {
	t.Parallel()
	m, dbs, _ := newTestAgent(t)
	dbs["CONFIG_DB"].hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "up"}
	got, status := m.GetInterface(t.Context(), &agent.Interface{Name: "Ethernet0"})
	if status != nil || got == nil || got.AliasName != "" {
		t.Fatalf("GetInterface: got=%+v status=%v", got, status)
	}
	list, status := m.ListInterfaces(t.Context())
	if status != nil || list == nil || len(list.Items) != 1 || list.Items[0].AliasName != "" {
		t.Fatalf("ListInterfaces: list=%+v status=%v", list, status)
	}
}

func TestSetInterfaceRejectsMalformedNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "Ethernet-1", "Ethernet0.1", "Ethernet0junk", "eth0-0junk", "eth0-4", "eth-1-0"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			dbs["CONFIG_DB"].hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "down"}
			input := &agent.Interface{Name: name, AdminStatus: agent.StatusUp, AliasName: "new"}
			_, adminStatus := m.SetInterfaceAdminStatus(t.Context(), input)
			_, aliasStatus := m.SetInterfaceAliasName(t.Context(), input)
			for _, status := range []*agent.Status{adminStatus, aliasStatus} {
				if status == nil || status.Code != agenterrors.BAD_REQUEST {
					t.Errorf("name=%q status=%v", name, status)
				}
			}
			if *saves != 0 || len(dbs["CONFIG_DB"].writes) != 0 {
				t.Fatal("invalid name caused a mutation")
			}
		})
	}
}

func TestListPortsChoosesLowestNumericMember(t *testing.T) {
	t.Parallel()
	m, dbs, _ := newTestAgent(t)
	dbs["CONFIG_DB"].hashes = map[string]map[string]string{
		"PORT|Ethernet8":  {"index": "0", "alias": "parent"},
		"PORT|Ethernet10": {"index": "0"},
	}
	got, status := m.ListPorts(t.Context())
	if status != nil || got == nil || len(got.Items) != 1 || got.Items[0].Name != "Ethernet8" {
		t.Fatalf("ports=%+v status=%v, want only Ethernet8", got, status)
	}
}

func TestGetInterfaceNeighborRemoteDescription(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, description, portID, want string }{
		{"SONiC", "Ethernet16", "unused", "eth4-0"},
		{"Linux", "ens1f0", "unused", "ens1f0"},
		{"description", "uplink to rack 1", "unused", "uplink to rack 1"},
		{"suffix", "Ethernet16 uplink", "unused", "Ethernet16 uplink"},
		{"subinterface", "Ethernet16.1", "unused", "Ethernet16.1"},
		{"invalid SONiC", "Ethernet-1", "unused", "Ethernet-1"},
		{"fallback", "", "Eth5(Port5)", "Eth5(Port5)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			dbs["APPL_DB"].hashes["LLDP_ENTRY_TABLE:Ethernet0"] = map[string]string{
				"lldp_rem_chassis_id": "02:00:00:00:00:02", "lldp_rem_sys_name": "neighbor",
				"lldp_rem_port_desc": tc.description, "lldp_rem_port_id": tc.portID,
			}
			got, status := m.GetInterfaceNeighbor(t.Context(), &agent.Interface{Name: "eth0-0"})
			if status != nil || got == nil || got.Handle != tc.want {
				t.Fatalf("neighbor=%+v status=%v, want handle=%q", got, status, tc.want)
			}
			if *saves != 0 || len(dbs["CONFIG_DB"].writes) != 0 {
				t.Fatal("LLDP read mutated config")
			}
		})
	}
}

func TestSetInterfaceCanceledSaveRollback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, field, old, desired        string
		missing, rollbackFails, retryOld bool
	}{
		{name: "admin retry desired", field: "admin_status", old: "down", desired: "up"},
		{name: "alias retry desired", field: "alias", old: "old", desired: "new"},
		{name: "absent admin", field: "admin_status", desired: "up", missing: true},
		{name: "absent alias", field: "alias", desired: "new", missing: true},
		{name: "admin retry restored", field: "admin_status", old: "down", desired: "up", retryOld: true},
		{name: "alias retry restored", field: "alias", old: "old", desired: "new", retryOld: true},
		{name: "failed admin rollback", field: "admin_status", old: "down", desired: "up", rollbackFails: true},
		{name: "failed alias rollback", field: "alias", old: "old", desired: "new", rollbackFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			config := dbs["CONFIG_DB"]
			fields := map[string]string{"index": "1"}
			if !tc.missing {
				fields[tc.field] = tc.old
			}
			before := maps.Clone(fields)
			config.hashes["PORT|Ethernet0"] = fields
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var rollbackCtx context.Context
			config.before = func(ctx context.Context, cmd redis.Cmder) {
				if *saves == 1 && (cmd.Name() == "hset" || cmd.Name() == "hdel") {
					rollbackCtx = ctx
					deadline, bounded := ctx.Deadline()
					if ctx.Err() != nil || !bounded || time.Until(deadline) > RedisDefaultTimeout {
						t.Errorf("rollback must have live bounded context: err=%v deadline=%v", ctx.Err(), deadline)
					}
				}
			}
			m.saveConfig = func(context.Context) *agent.Status {
				(*saves)++
				cancel()
				if tc.rollbackFails {
					config.fail["hset"] = fmt.Errorf("rollback unavailable")
				}
				return agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "save outcome uncertain: context canceled")
			}
			set := func(ctx context.Context, value string) *agent.Status {
				input := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.DeviceStatus(value), AliasName: value}
				var status *agent.Status
				if tc.field == "alias" {
					_, status = m.SetInterfaceAliasName(ctx, input)
				} else {
					_, status = m.SetInterfaceAdminStatus(ctx, input)
				}
				return status
			}
			status := set(ctx, tc.desired)
			if status == nil || !strings.Contains(status.Message, "save outcome uncertain") {
				t.Errorf("expected original save failure, got %v", status)
			}
			if !tc.rollbackFails && !reflect.DeepEqual(fields, before) {
				t.Errorf("rollback fields=%v, want=%v", fields, before)
			}
			if rollbackCtx == nil || rollbackCtx.Err() == nil {
				t.Error("rollback context must be released after use")
			}
			config.before = nil
			delete(config.fail, "hset")
			m.saveConfig = func(context.Context) *agent.Status { (*saves)++; return nil }
			retry := tc.desired
			if tc.retryOld {
				retry = tc.old
			}
			if status := set(t.Context(), retry); status != nil {
				t.Fatalf("retry failed: %v", status)
			}
			if *saves != 2 || fields[tc.field] != retry {
				t.Fatalf("retry skipped persistence: saves=%d fields=%v", *saves, fields)
			}
			writes := len(config.writes)
			if status := set(t.Context(), retry); status != nil || *saves != 2 || len(config.writes) != writes {
				t.Fatalf("confirmed no-op should not write/save: status=%v saves=%d", status, *saves)
			}
		})
	}
}

func TestSetInterfaceUncertainPersistenceRetry(t *testing.T) {
	t.Parallel()
	m, dbs, saves := newTestAgent(t)
	config := dbs["CONFIG_DB"]
	config.hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "down", "alias": "existing"}
	m.saveConfig = func(context.Context) *agent.Status {
		(*saves)++
		return agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "save uncertain")
	}
	_, status := m.SetInterfaceAdminStatus(t.Context(), &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp})
	if status == nil {
		t.Fatal("expected failed save")
	}
	writes := len(config.writes)
	// A matching request for another field must not conceal the failed whole-DB save.
	input := &agent.Interface{Name: "Ethernet0", AliasName: "existing"}
	_, status = m.SetInterfaceAliasName(t.Context(), input)
	if status == nil || *saves != 2 || len(config.writes) != writes {
		t.Fatalf("failed persistence retry: status=%v saves=%d writes=%v", status, *saves, config.writes)
	}
	m.saveConfig = func(context.Context) *agent.Status { (*saves)++; return nil }
	_, status = m.SetInterfaceAliasName(t.Context(), input)
	if status != nil || *saves != 3 || len(config.writes) != writes {
		t.Fatalf("successful persistence retry: status=%v saves=%d writes=%v", status, *saves, config.writes)
	}
	_, status = m.SetInterfaceAliasName(t.Context(), input)
	if status != nil || *saves != 3 || len(config.writes) != writes {
		t.Fatalf("confirmed no-op: status=%v saves=%d writes=%v", status, *saves, config.writes)
	}
}
