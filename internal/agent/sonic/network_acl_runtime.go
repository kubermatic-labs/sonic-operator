// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

type aclReader func(context.Context, string, string) (map[string]string, error)
type aclScanner func(context.Context, string, string) (vlanChangeDB, error)

const aclASIC = "ASIC_STATE:SAI_OBJECT_TYPE_"

// All production observations use the agent's connection pool. Tests supply
// readers/scanners or real disposable Redis clients, never fabricated readiness.
func (m *SonicAgent) aclRead(ctx context.Context, db, key string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := m.Connect(db)
	if err != nil {
		return nil, err
	}
	return r.HGetAll(ctx, key).Result()
}

func (m *SonicAgent) aclScan(ctx context.Context, db, prefix string) (vlanChangeDB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := m.Connect(db)
	if err != nil {
		return nil, err
	}
	out := vlanChangeDB{}
	var cursor uint64
	for {
		keys, next, err := r.Scan(ctx, cursor, prefix+"*", 256).Result()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			if len(out) >= 16384 {
				return nil, fmt.Errorf("ACL observation exceeds bounded scan")
			}
			fields, err := r.HGetAll(ctx, key).Result()
			if err != nil {
				return nil, err
			}
			out[key] = fields
		}
		cursor = next
		if cursor == 0 {
			return out, nil
		}
	}
}

func aclCapability(ctx context.Context, read aclReader, creating bool) error {
	fields, err := read(ctx, "STATE_DB", "ACL_STAGE_CAPABILITY_TABLE|INGRESS")
	if err != nil {
		return err
	}
	if !strings.Contains(","+fields["action_list"]+",", ",PACKET_ACTION,") || (fields["is_action_list_mandatory"] != "false" && fields["is_action_list_mandatory"] != "true") {
		return fmt.Errorf("unsupported or absent ingress ACL packet-action capability")
	}
	if creating {
		// Both bind point types are in the built-in L3/L3V6 table definition.
		for _, kind := range []string{"PORT", "LAG"} {
			crm, err := read(ctx, "COUNTERS_DB", "CRM:ACL_STATS:INGRESS:"+kind)
			if err != nil {
				return err
			}
			n, err := strconv.ParseUint(crm["crm_stats_acl_table_available"], 10, 64)
			if err != nil || n == 0 {
				return fmt.Errorf("ACL table capacity unavailable for %s", kind)
			}
		}
	}
	return nil
}

type aclRuleObserved struct {
	Status     string  `json:"status"`
	EntryOID   string  `json:"entryOID,omitempty"`
	CounterOID string  `json:"counterOID,omitempty"`
	Packets    *uint64 `json:"packets,omitempty"`
	Bytes      *uint64 `json:"bytes,omitempty"`
	Verified   bool    `json:"verified"`
}

type aclObserved struct {
	Policy           string                     `json:"policy"`
	TableStatus      string                     `json:"tableStatus"`
	TableOID         string                     `json:"tableOID,omitempty"`
	ExpectedRules    int                        `json:"expectedRules"`
	AppliedRules     int                        `json:"appliedRules"`
	ObservedEntries  int                        `json:"observedEntries"`
	ObservedCounters int                        `json:"observedCounters"`
	Rules            map[string]aclRuleObserved `json:"rules"`
	Bindings         map[string]string          `json:"bindings"`
	Reason           string                     `json:"reason,omitempty"`
}

func aclEntryDesired(fields map[string]string, table, counter string) map[string]string {
	out := map[string]string{
		"SAI_ACL_ENTRY_ATTR_TABLE_ID":             table,
		"SAI_ACL_ENTRY_ATTR_PRIORITY":             fields["PRIORITY"],
		"SAI_ACL_ENTRY_ATTR_ADMIN_STATE":          "true",
		"SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION": "SAI_PACKET_ACTION_" + fields["PACKET_ACTION"],
		"SAI_ACL_ENTRY_ATTR_ACTION_COUNTER":       counter,
	}
	for field, value := range fields {
		attr := field
		switch field {
		case "PRIORITY", "PACKET_ACTION":
			continue
		case "IP_TYPE":
			attr, value = "ACL_IP_TYPE", "SAI_ACL_IP_TYPE_"+value+"&mask:0xffffffffffffffff"
		case "SRC_IP", "DST_IP", "SRC_IPV6", "DST_IPV6":
			p, err := netip.ParsePrefix(value)
			if err != nil {
				return nil
			}
			mask := net.CIDRMask(p.Bits(), p.Addr().BitLen())
			a, ok := netip.AddrFromSlice(mask)
			if !ok {
				return nil
			}
			value = p.Addr().String() + "&mask:" + a.String()
		case "NEXT_HEADER":
			attr, value = "IPV6_NEXT_HEADER", value+"&mask:0xff"
		case "IP_PROTOCOL":
			value += "&mask:0xff"
		case "L4_SRC_PORT", "L4_DST_PORT":
			value += "&mask:0xffff"
		default:
			return nil
		}
		out["SAI_ACL_ENTRY_ATTR_FIELD_"+attr] = value
	}
	return out
}

func aclTableMatches(table map[string]string, desired vlanChangeDB) bool {
	if table["SAI_ACL_TABLE_ATTR_ACL_STAGE"] != "SAI_ACL_STAGE_INGRESS" {
		return false
	}
	for key, fields := range desired {
		if !strings.HasPrefix(key, "ACL_RULE|") {
			continue
		}
		for attr := range aclEntryDesired(fields, "", "") {
			if strings.HasPrefix(attr, "SAI_ACL_ENTRY_ATTR_FIELD_") && table[strings.Replace(attr, "ENTRY", "TABLE", 1)] != "true" {
				return false
			}
		}
	}
	return true
}

// Correlation is rule name -> ACL_COUNTER_RULE_MAP -> counter TABLE_ID ->
// exact entry ACTION_COUNTER. Never infer table identity from global CRM totals
// or from an arbitrary table that happens to contain similar rules.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func aclRuntime(ctx context.Context, name string, desired vlanChangeDB, ports []string, read aclReader, scan aclScanner) (bool, json.RawMessage, error) {
	o := aclObserved{Policy: name, ExpectedRules: len(desired) - 1, Rules: map[string]aclRuleObserved{}, Bindings: map[string]string{}}
	finish := func(ok bool, reason string, err error) (bool, json.RawMessage, error) {
		o.Reason = reason
		raw, _ := json.Marshal(o)
		return ok, raw, err
	}
	if err := aclCapability(ctx, read, false); err != nil {
		return finish(false, "capability unavailable", err)
	}
	applied, err := aclReadApplied(ctx, read)
	if err != nil {
		return finish(false, "VIDTORID read failed", err)
	}
	state, err := read(ctx, "STATE_DB", "ACL_TABLE_TABLE|"+name)
	if err != nil {
		return finish(false, "table state read failed", err)
	}
	o.TableStatus = state["status"]
	counterMap, err := read(ctx, "COUNTERS_DB", "ACL_COUNTER_RULE_MAP")
	if err != nil {
		return finish(false, "counter map read failed", err)
	}
	entries, err := scan(ctx, "ASIC_DB", aclASIC+"ACL_ENTRY:")
	if err != nil {
		return finish(false, "entry read failed", err)
	}
	valid := o.TableStatus == "Active"
	usedCounters, usedEntries := map[string]bool{}, map[string]bool{}
	for key, fields := range desired {
		if !strings.HasPrefix(key, "ACL_RULE|"+name+"|") {
			continue
		}
		rule := strings.TrimPrefix(key, "ACL_RULE|"+name+"|")
		rs, err := read(ctx, "STATE_DB", "ACL_RULE_TABLE|"+name+"|"+rule)
		if err != nil {
			return finish(false, "rule state read failed", err)
		}
		counter := counterMap[name+":"+rule]
		ro := aclRuleObserved{Status: rs["status"], CounterOID: counter}
		o.Rules[rule] = ro
		if !applied.object(counter, "ACL_COUNTER") || usedCounters[counter] {
			valid = false
			continue
		}
		aliases := 0
		for _, oid := range counterMap {
			if oid == counter {
				aliases++
			}
		}
		if aliases != 1 {
			valid = false
			continue
		}
		usedCounters[counter] = true
		cf, err := read(ctx, "ASIC_DB", aclASIC+"ACL_COUNTER:"+counter)
		if err != nil {
			return finish(false, "counter ASIC read failed", err)
		}
		table := cf["SAI_ACL_COUNTER_ATTR_TABLE_ID"]
		if !applied.object(table, "ACL_TABLE") {
			valid = false
			continue
		}
		if o.TableOID == "" {
			o.TableOID = table
		}
		if o.TableOID != table {
			valid = false
			continue
		}
		matches := 0
		for ek, ef := range entries {
			if ef["SAI_ACL_ENTRY_ATTR_ACTION_COUNTER"] == counter {
				matches++
				if reflect.DeepEqual(ef, aclEntryDesired(fields, table, counter)) && !usedEntries[ek] {
					ro.EntryOID = strings.TrimPrefix(ek, aclASIC+"ACL_ENTRY:")
				}
			}
		}
		stats, err := read(ctx, "COUNTERS_DB", "COUNTERS:"+counter)
		if err != nil {
			return finish(false, "runtime counter read failed", err)
		}
		packets, pe := strconv.ParseUint(stats["SAI_ACL_COUNTER_ATTR_PACKETS"], 10, 64)
		bytes, be := strconv.ParseUint(stats["SAI_ACL_COUNTER_ATTR_BYTES"], 10, 64)
		if pe == nil {
			ro.Packets = &packets
		}
		if be == nil {
			ro.Bytes = &bytes
		}
		ro.Verified = rs["status"] == "Active" && matches == 1 && applied.object(ro.EntryOID, "ACL_ENTRY") && cf["SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT"] == "true" && cf["SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT"] == "true" && pe == nil && be == nil
		if ro.Verified {
			o.AppliedRules++
			usedEntries[aclASIC+"ACL_ENTRY:"+ro.EntryOID] = true
		} else {
			valid = false
		}
		o.Rules[rule] = ro
	}
	if o.TableOID == "" {
		return finish(false, "table cannot be correlated to named rule counters", nil)
	}
	for _, fields := range entries {
		if fields["SAI_ACL_ENTRY_ATTR_TABLE_ID"] == o.TableOID {
			o.ObservedEntries++
		}
	}
	counters, err := scan(ctx, "ASIC_DB", aclASIC+"ACL_COUNTER:")
	if err != nil {
		return finish(false, "counter scan failed", err)
	}
	for _, fields := range counters {
		if fields["SAI_ACL_COUNTER_ATTR_TABLE_ID"] == o.TableOID {
			o.ObservedCounters++
		}
	}
	for rule := range counterMap {
		if strings.HasPrefix(rule, name+":") {
			if _, ok := o.Rules[strings.TrimPrefix(rule, name+":")]; !ok {
				valid = false
			}
		}
	}
	table, err := read(ctx, "ASIC_DB", aclASIC+"ACL_TABLE:"+o.TableOID)
	if err != nil {
		return finish(false, "table ASIC read failed", err)
	}
	valid = valid && aclTableMatches(table, desired) && o.ObservedEntries == o.ExpectedRules && o.ObservedCounters == o.ExpectedRules
	bound, bindings, err := aclBindings(ctx, o.TableOID, ports, read, scan, applied)
	o.Bindings = bindings
	if err != nil {
		return finish(false, "binding read failed", err)
	}
	if !valid || !bound {
		return finish(false, "incomplete or conflicting ACL runtime evidence", nil)
	}
	stable, err := applied.stable(ctx, read)
	if err != nil || !stable {
		o.AppliedRules = 0
		for rule, ro := range o.Rules {
			ro.Verified = false
			o.Rules[rule] = ro
		}
		return finish(false, "ACL translations changed during observation", err)
	}
	return finish(true, "", ctx.Err())
}

func aclPortObjects(ctx context.Context, ports []string, read aclReader) (map[string]string, error) {
	applied, err := aclReadApplied(ctx, read)
	if err != nil {
		return nil, err
	}
	objects, err := aclAppliedPortObjects(ctx, ports, read, applied)
	if err != nil {
		return nil, err
	}
	stable, err := applied.stable(ctx, read)
	if err != nil {
		return nil, err
	}
	if !stable {
		return nil, fmt.Errorf("ACL interface translations changed")
	}
	return objects, nil
}

func aclAppliedPortObjects(ctx context.Context, ports []string, read aclReader, applied *aclApplied) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range ports {
		typ, state := "PORT", "PORT_TABLE"
		if strings.HasPrefix(name, "PortChannel") {
			typ, state = "LAG", "LAG_TABLE"
		}
		mapping, err := read(ctx, "COUNTERS_DB", "COUNTERS_"+typ+"_NAME_MAP")
		if err != nil {
			return nil, err
		}
		oid := mapping[name]
		if !applied.object(oid, typ) {
			return nil, fmt.Errorf("ACL interface %s has no applied %s OID", name, typ)
		}
		fields, err := read(ctx, "STATE_DB", state+"|"+name)
		if err != nil {
			return nil, err
		}
		if fields["state"] != "ok" {
			return nil, fmt.Errorf("ACL interface %s is not ready", name)
		}
		key := aclASIC + typ + ":" + oid
		object, err := read(ctx, "ASIC_DB", key)
		if err != nil {
			return nil, err
		}
		if len(object) == 0 || out[key] != "" {
			return nil, fmt.Errorf("ACL interface OID missing or aliased")
		}
		out[key] = name
	}
	return out, nil
}

// Prove the complete attachment set, including unexpected ports and direct
// switch/VLAN/RIF attachments. An unbound policy must have no group members.
func aclBindings(ctx context.Context, table string, ports []string, read aclReader, scan aclScanner, applied *aclApplied) (bool, map[string]string, error) {
	observed := map[string]string{}
	wanted, err := aclAppliedPortObjects(ctx, ports, read, applied)
	if err != nil {
		return false, observed, err
	}
	members, err := scan(ctx, "ASIC_DB", aclASIC+"ACL_TABLE_GROUP_MEMBER:")
	if err != nil {
		return false, observed, err
	}
	groups := map[string]int{}
	valid := applied.object(table, "ACL_TABLE")
	for key, f := range members {
		if f["SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID"] == table {
			if !applied.object(strings.TrimPrefix(key, aclASIC+"ACL_TABLE_GROUP_MEMBER:"), "ACL_TABLE_GROUP_MEMBER") {
				valid = false
			}
			groups[f["SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID"]]++
		}
	}
	valid = valid && len(groups) == len(ports)
	for group, n := range groups {
		if !applied.object(group, "ACL_TABLE_GROUP") || n != 1 {
			valid = false
			continue
		}
		fields, err := read(ctx, "ASIC_DB", aclASIC+"ACL_TABLE_GROUP:"+group)
		if err != nil {
			return false, observed, err
		}
		if fields["SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE"] != "SAI_ACL_STAGE_INGRESS" || fields["SAI_ACL_TABLE_GROUP_ATTR_TYPE"] != "SAI_ACL_TABLE_GROUP_TYPE_PARALLEL" {
			valid = false
		}
	}
	seenGroups := map[string]bool{}
	for _, typ := range []string{"PORT", "LAG", "VLAN", "ROUTER_INTERFACE", "SWITCH"} {
		objects, err := scan(ctx, "ASIC_DB", aclASIC+typ+":")
		if err != nil {
			return false, observed, err
		}
		for key, fields := range objects {
			for field, oid := range fields {
				if !strings.HasSuffix(field, "_ACL") || (groups[oid] == 0 && oid != table) {
					continue
				}
				name := wanted[key]
				if name == "" || field != "SAI_"+typ+"_ATTR_INGRESS_ACL" || groups[oid] != 1 || seenGroups[oid] {
					valid = false
				}
				if name == "" {
					name = key
				}
				observed[name] = oid
				seenGroups[oid] = true
			}
		}
	}
	return valid && len(observed) == len(ports) && len(seenGroups) == len(groups), observed, nil
}
