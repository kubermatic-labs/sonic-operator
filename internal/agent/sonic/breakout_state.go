// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

func validateBreakoutRequest(r *agent.PortBreakoutRequest) error {
	if r == nil {
		return fmt.Errorf("breakout request required")
	}
	if _, valid := ethernetNumber(r.Port); !valid {
		return fmt.Errorf("canonical Ethernet parent required")
	}
	if len(r.Mode) > 64 || !vlanAuthorityBreakoutMode.MatchString(r.Mode) {
		return fmt.Errorf("invalid breakout mode")
	}
	if r.ChildAdminState != "up" && r.ChildAdminState != "down" {
		return fmt.Errorf("child admin state must be lowercase up or down")
	}
	return nil
}

func breakoutNames(p *breakoutPlatform) map[string]bool {
	names := map[string]bool{}
	for _, children := range p.Modes {
		for name := range children {
			names[name] = true
		}
	}
	return names
}

func breakoutTarget(db vlanChangeDB, p *breakoutPlatform) vlanChangeDB {
	target := vlanChangeDB{}
	for name := range breakoutNames(p) {
		if fields, ok := db["PORT|"+name]; ok {
			target["PORT|"+name] = maps.Clone(fields)
		}
	}
	if fields, ok := db["BREAKOUT_CFG|"+p.Port]; ok {
		target["BREAKOUT_CFG|"+p.Port] = maps.Clone(fields)
	}
	return target
}

func breakoutUnrelatedHash(db vlanChangeDB, p *breakoutPlatform) string {
	other := maps.Clone(db)
	for key := range breakoutTarget(db, p) {
		delete(other, key)
	}
	return vlanAuthorityHash(other)
}

func breakoutConfigMatches(db vlanChangeDB, p *breakoutPlatform, mode string) error {
	expected, ok := p.Modes[mode]
	if !ok {
		return fmt.Errorf("mode is not an exact platform capability")
	}
	meta := db["BREAKOUT_CFG|"+p.Port]
	if len(meta) != 1 || meta["brkout_mode"] != mode {
		return fmt.Errorf("BREAKOUT_CFG mode not verified")
	}
	lanes, _ := breakoutLanes(p.Lanes)
	names := breakoutNames(p)
	for key, fields := range db {
		if !strings.HasPrefix(key, "PORT|") {
			continue
		}
		name := strings.TrimPrefix(key, "PORT|")
		if want, ok := expected[name]; ok {
			for _, field := range []string{"lanes", "speed", "index", "subport"} {
				if value, present := want[field]; present && fields[field] != value {
					return fmt.Errorf("%s %s not verified", name, field)
				}
			}
		} else {
			if names[name] {
				return fmt.Errorf("deleted child %s still present", name)
			}
			for _, lane := range strings.Split(fields["lanes"], ",") {
				if lanes[lane] {
					return fmt.Errorf("foreign PORT overlaps parent lanes")
				}
			}
		}
	}
	for name := range expected {
		if len(db["PORT|"+name]) == 0 {
			return fmt.Errorf("missing child %s", name)
		}
	}
	return nil
}

// Unknown tables fail closed even for opaque selectors ("all", aliases, ranges).
// This allowlist covers non-port system configuration only; it is not a blanket
// dependency deletion list. Explicit references are checked even in known tables.
func breakoutDependencies(db vlanChangeDB, p *breakoutPlatform) error {
	names := breakoutNames(p)
	refs := []string{}
	for name := range names {
		refs = append(refs, regexp.QuoteMeta(name))
		if alias := db["PORT|"+name]["alias"]; alias != "" {
			refs = append(refs, regexp.QuoteMeta(alias))
		}
	}
	ref := regexp.MustCompile(`(^|[^a-zA-Z0-9])(` + strings.Join(refs, "|") + `)([^a-zA-Z0-9]|$)`)
	for key, fields := range db {
		table, identity, _ := strings.Cut(key, "|")
		if table == "VLAN" {
			id, err := strconv.ParseUint(strings.TrimPrefix(identity, "Vlan"), 10, 32)
			if err != nil || id < 1 || id > 4094 || identity != fmt.Sprintf("Vlan%d", id) || len(fields) != 1 || fields["vlanid"] != fmt.Sprint(id) {
				return fmt.Errorf("unknown or legacy VLAN fields/selector")
			}
		}
		if table == "VLAN_MEMBER" {
			parts := strings.Split(identity, "|")
			if len(parts) != 2 || len(fields) != 1 || (fields["tagging_mode"] != "tagged" && fields["tagging_mode"] != "untagged") {
				return fmt.Errorf("unknown VLAN member grammar")
			}
			id, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "Vlan"), 10, 32)
			valid := vlanMemberNameValid(parts[1])
			if err != nil || id < 1 || id > 4094 || parts[0] != fmt.Sprintf("Vlan%d", id) || !valid {
				return fmt.Errorf("noncanonical VLAN member or opaque selector")
			}
		}
		if table == "PORTCHANNEL" || table == "PORTCHANNEL_MEMBER" || table == "INTERFACE" || table == "PORTCHANNEL_INTERFACE" || table == "VLAN_INTERFACE" || table == "VRF" {
			if err := lagL3DependencyGrammar(key, fields); err != nil {
				return err
			}
			// Canonical rows are safe to inspect for exact affected ports below.
			// Unknown fields, aliases and opaque selectors still fail closed.
		}
		if table == "PORT" {
			if names[identity] {
				continue
			}
			// References in unrelated PORT fields are still dependencies.
		} else if table == "BREAKOUT_CFG" {
			if _, valid := ethernetNumber(identity); !valid || len(fields) != 1 || !vlanAuthorityBreakoutMode.MatchString(fields["brkout_mode"]) {
				return fmt.Errorf("malformed BREAKOUT_CFG metadata")
			}
			continue
		} else if table == "LOGGER" {
			// Reuse the narrowly validated LOGGER grammar, without any VLAN target.
			if err := vlanAuthoritySafe(vlanChangeDB{key: fields}, 4094, vlanChangeDB{}); err != nil {
				return err
			}
			continue
		} else {
			switch table {
			case "CONFIG_DB_INITIALIZED", "DEVICE_METADATA", "AUTO_TECHSUPPORT", "AUTO_TECHSUPPORT_FEATURE", "BANNER_MESSAGE", "BGP_DEVICE_GLOBAL", "CRM", "FEATURE", "FLEX_COUNTER_TABLE", "KDUMP", "MGMT_INTERFACE", "MGMT_PORT", "MGMT_VRF_CONFIG", "NTP", "NTP_SERVER", "PASSW_HARDENING", "SNMP", "SNMP_COMMUNITY", "SNMP_LOCATION", "SNMP_CONTACT", "SYSLOG_CONFIG", "SYSLOG_CONFIG_FEATURE", "SYSLOG_SERVER", "SYSTEM_DEFAULTS", "VERSIONS", "TACPLUS", "TACPLUS_SERVER", "AAA", "DNS_NAMESERVER", "VLAN", "VLAN_MEMBER", "PORTCHANNEL", "PORTCHANNEL_MEMBER", "INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "VRF":
			default:
				return fmt.Errorf("unknown or unsupported dependency table %s; inspect before breakout", table)
			}
		}
		if ref.MatchString(key) {
			return fmt.Errorf("breakout dependency in %s", key)
		}
		for field, value := range fields {
			if ref.MatchString(field) || ref.MatchString(value) {
				return fmt.Errorf("breakout dependency in %s field %s", key, field)
			}
		}
	}
	return nil
}

// Preserve understood configurable fields for names that survive and inherit
// MTU for new names only when all old children agree. Native topology fields and
// lane-dependent FEC come from SONiC, not from the former lane configuration.
func breakoutTargets(db vlanChangeDB, p *breakoutPlatform, r agent.PortBreakoutRequest) (vlanChangeDB, vlanChangeDB, error) {
	if p.NativeModes[r.Mode] == nil {
		return nil, nil, fmt.Errorf("native addition model required before mutation")
	}
	native := vlanChangeDB{"BREAKOUT_CFG|" + p.Port: {"brkout_mode": r.Mode}}
	after := vlanChangeDB{"BREAKOUT_CFG|" + p.Port: {"brkout_mode": r.Mode}}
	mtu := ""
	firstMTU := true
	for name := range p.Modes[db["BREAKOUT_CFG|"+p.Port]["brkout_mode"]] {
		fields := db["PORT|"+name]
		if firstMTU {
			mtu = fields["mtu"]
			firstMTU = false
		} else if fields["mtu"] != mtu {
			return nil, nil, fmt.Errorf("old children have different MTUs; normalize explicitly before breakout")
		}
		for field := range fields {
			switch field {
			case "lanes", "speed", "index", "subport", "fec", "alias", "admin_status", "mtu", "description", "dhcp_rate_limit":
			default:
				currentMode := db["BREAKOUT_CFG|"+p.Port]["brkout_mode"]
				if value, ok := p.NativeModes[currentMode][name][field]; !ok || value != fields[field] {
					return nil, nil, fmt.Errorf("unsupported target PORT field %s; explicit recovery/preservation policy required", field)
				}
			}
		}
	}
	for name, generated := range p.NativeModes[r.Mode] {
		native["PORT|"+name] = maps.Clone(generated)
		fields := maps.Clone(generated)
		old := db["PORT|"+name]
		for _, key := range []string{"alias", "mtu", "description", "dhcp_rate_limit"} {
			if value, ok := old[key]; ok {
				fields[key] = value
			}
		}
		if fields["mtu"] == "" && mtu != "" {
			fields["mtu"] = mtu
		}
		fields["admin_status"] = r.ChildAdminState
		if old != nil {
			// Identity is the native name, even though the CLI recreates its PORT.
			// An omitted old admin_status has SONiC's effective default, down.
			fields["admin_status"] = old["admin_status"]
			if fields["admin_status"] == "" {
				fields["admin_status"] = "down"
			}
			if fields["admin_status"] != "up" && fields["admin_status"] != "down" {
				return nil, nil, fmt.Errorf("invalid surviving admin state")
			}
		}
		after["PORT|"+name] = fields
	}
	return native, after, nil
}

func breakoutResult(db vlanChangeDB, p *breakoutPlatform, r *breakoutRecord) *agent.PortBreakout {
	out := &agent.PortBreakout{Port: p.Port, Mode: db["BREAKOUT_CFG|"+p.Port]["brkout_mode"]}
	for mode := range p.Modes {
		out.SupportedModes = append(out.SupportedModes, mode)
	}
	sort.Strings(out.SupportedModes)
	for name := range breakoutNames(p) {
		if f := db["PORT|"+name]; len(f) > 0 {
			out.Children = append(out.Children, agent.PortBreakoutChild{Name: name, Lanes: f["lanes"], Speed: f["speed"], AdminState: f["admin_status"], MTU: f["mtu"]})
		}
	}
	sort.Slice(out.Children, func(i, j int) bool {
		a, _ := ethernetNumber(out.Children[i].Name)
		b, _ := ethernetNumber(out.Children[j].Name)
		return a < b
	})
	out.Pending = r != nil && r.Pending
	return out
}

// Unlike Connect, these clients never perform unbounded background health probes.
func (m *SonicAgent) breakoutDB(name string) *redis.Client {
	m.poolMutex.Lock()
	defer m.poolMutex.Unlock()
	if m.clientPool == nil {
		m.clientPool = map[string]*redis.Client{}
	}
	if m.clientPool[name] == nil {
		m.clientPool[name] = redis.NewClient(&redis.Options{Addr: m.redisAddr, DB: getRedisDBIDByName(name), DialTimeout: RedisDefaultTimeout, ReadTimeout: RedisDefaultTimeout, WriteTimeout: RedisDefaultTimeout, PoolTimeout: RedisDefaultTimeout, MaxRetries: -1, ContextTimeoutEnabled: true, DisableIndentity: true})
	}
	return m.clientPool[name]
}

func (m *SonicAgent) readBreakoutDB(ctx context.Context) (vlanChangeDB, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if m.breakoutSnapshot != nil {
		return m.breakoutSnapshot(ctx)
	}
	cmd := &vlanCommand{redis.NewCmd(ctx, "eval", vlanChangeReadScript, 0)}
	if err := m.breakoutDB("CONFIG_DB").Process(ctx, cmd); err != nil {
		return nil, "", err
	}
	raw, err := cmd.Text()
	if err != nil {
		return nil, "", err
	}
	var rows []struct {
		Key    string            `json:"key"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, "", err
	}
	db := vlanChangeDB{}
	for _, row := range rows {
		db[row.Key] = row.Fields
	}
	return db, raw, nil
}

func (m *SonicAgent) restoreBreakoutAttributes(ctx context.Context, raw string, before, after vlanChangeDB) (bool, error) {
	if m.breakoutCAS != nil {
		return m.breakoutCAS(ctx, raw, before, after)
	}
	changes := []struct {
		Key    string            `json:"key"`
		Remove []string          `json:"remove"`
		Set    map[string]string `json:"set"`
	}{}
	for key, fields := range after {
		if len(before[key]) == 0 {
			return false, fmt.Errorf("refusing to create missing PORT during attribute restoration")
		}
		set := map[string]string{}
		for field, value := range fields {
			if before[key][field] != value {
				set[field] = value
			}
		}
		if len(set) != 0 {
			changes = append(changes, struct {
				Key    string            `json:"key"`
				Remove []string          `json:"remove"`
				Set    map[string]string `json:"set"`
			}{key, []string{}, set})
		}
	}
	data, err := json.Marshal(changes)
	if err != nil {
		return false, err
	}
	cmd := &vlanCommand{redis.NewCmd(ctx, "eval", vlanChangeCASScript, 0, raw, string(data))}
	if err := m.breakoutDB("CONFIG_DB").Process(ctx, cmd); err != nil {
		return false, err
	}
	n, err := cmd.Int64()
	return n == 1, err
}

func (m *SonicAgent) checkBreakoutRuntime(ctx context.Context, p *breakoutPlatform, target vlanChangeDB) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.verifyBreakoutRuntime != nil {
		return m.verifyBreakoutRuntime(ctx, p, target)
	}
	rdb := m.breakoutDB("APPL_DB")
	keys, err := rdb.Keys(ctx, "PORT_TABLE:*").Result()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	lanes, _ := breakoutLanes(p.Lanes)
	names := breakoutNames(p)
	for _, key := range keys {
		name := strings.TrimPrefix(key, "PORT_TABLE:")
		fields, err := rdb.HGetAll(ctx, key).Result()
		if err != nil {
			return err
		}
		if want, ok := target["PORT|"+name]; ok {
			for _, field := range []string{"lanes", "speed", "admin_status", "mtu"} {
				if value, ok := want[field]; ok && fields[field] != value {
					return fmt.Errorf("APPL_DB %s %s mismatch", name, field)
				}
			}
			seen[name] = true
		} else {
			if names[name] {
				return fmt.Errorf("deleted APPL_DB child still present")
			}
			for _, lane := range strings.Split(fields["lanes"], ",") {
				if lanes[lane] {
					return fmt.Errorf("foreign APPL_DB child overlaps lanes")
				}
			}
		}
	}
	for name := range names {
		_, wanted := target["PORT|"+name]
		if wanted && !seen[name] {
			return fmt.Errorf("missing APPL_DB child %s", name)
		}
		link, err := m.getLinkByName(name)
		if wanted {
			if err != nil || link == nil {
				return fmt.Errorf("missing kernel child %s", name)
			}
		} else {
			var notFound netlink.LinkNotFoundError
			if !errors.As(err, &notFound) {
				return fmt.Errorf("deleted kernel child %s not proven absent", name)
			}
		}
	}
	return ctx.Err()
}

func (m *SonicAgent) waitBreakoutRuntime(ctx context.Context, p *breakoutPlatform, target vlanChangeDB, hash string) error {
	for {
		db, _, err := m.readBreakoutDB(ctx)
		if err == nil && (breakoutUnrelatedHash(db, p) != hash || !reflect.DeepEqual(breakoutTarget(db, p), target)) {
			return fmt.Errorf("CONFIG_DB changed during convergence; manual inspection required")
		}
		if err == nil {
			err = m.checkBreakoutRuntime(ctx, p, target)
		}
		if err == nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("runtime convergence pending: %w: %v", ctx.Err(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
