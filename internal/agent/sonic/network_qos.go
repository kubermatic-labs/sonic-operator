// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"regexp"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Native contract verified read-only on SONiC 202511 (4784cca11), and against
// sonic-net/sonic-swss, branch 202511, orchagent/qosorch.{h,cpp}:
// map names are literal CONFIG_DB names; scheduler cir/pir are passed unchanged
// to SAI MIN/MAX_BANDWIDTH_RATE, cbs/pbs to MIN/MAX_BANDWIDTH_BURST_RATE.
// Bytes means bytes/sec (NOT bits/sec); bursts are bytes, or packets for Packets.
// Installed sonic-scheduler.yang additionally limits bursts to uint32 and
// requires cir for pir/cbs, pir for pbs, pir>=cir, and pbs>=cbs.
// The YANG's "policer" prose does not imply ACL/rule policing support.

var qosNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][-a-zA-Z0-9_]{0,31}$`)
var qosPortPattern = regexp.MustCompile(`^Ethernet(0|[1-9][0-9]*)$`)

type qosMapKind struct{ table, field, sai, from, to string }

var qosMapKinds = map[string]qosMapKind{
	"TCToPriorityGroup": {"TC_TO_PRIORITY_GROUP_MAP", "tc_to_pg_map", "TC_TO_PRIORITY_GROUP", "tc", "pg"},
	"DSCPToTC":          {"DSCP_TO_TC_MAP", "dscp_to_tc_map", "DSCP_TO_TC", "dscp", "tc"},
	"Dot1pToTC":         {"DOT1P_TO_TC_MAP", "dot1p_to_tc_map", "DOT1P_TO_TC", "dot1p", "tc"},
	"TCToQueue":         {"TC_TO_QUEUE_MAP", "tc_to_queue_map", "TC_TO_QUEUE", "tc", "qidx"},
}

type qosMapSpec struct {
	routingSpecMeta
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Entries []json.RawMessage `json:"entries"`
}

type qosSchedulerSpec struct {
	routingSpecMeta
	Name           string  `json:"name"`
	Algorithm      string  `json:"algorithm"`
	Weight         *uint32 `json:"weight"`
	MeterType      string  `json:"meterType"`
	CommittedRate  *uint64 `json:"committedRate"`
	PeakRate       *uint64 `json:"peakRate"`
	CommittedBurst *uint64 `json:"committedBurst"`
	PeakBurst      *uint64 `json:"peakBurst"`
}

type qosBindingSpec struct {
	routingSpecMeta
	InterfaceName     string            `json:"interfaceName"`
	DSCPToTC          string            `json:"dscpToTC"`
	Dot1pToTC         string            `json:"dot1pToTC"`
	TCToQueue         string            `json:"tcToQueue"`
	TCToPriorityGroup string            `json:"tcToPriorityGroup"`
	Queues            []json.RawMessage `json:"queues"`
}

func qosUint(v uint64) string { return strconv.FormatUint(v, 10) }

func qosNumber(s string, max uint64) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v > max || qosUint(v) != s {
		return 0, fmt.Errorf("invalid canonical QoS integer")
	}
	return v, nil
}

func qosMeta(meta routingSpecMeta) error {
	if meta.ManagementPolicy != "" && meta.ManagementPolicy != "Observe" && meta.ManagementPolicy != "Manage" {
		return fmt.Errorf("invalid managementPolicy")
	}
	return nil
}

func qosMapDefinition(table string) (qosMapKind, bool) {
	for _, kind := range qosMapKinds {
		if kind.table == table {
			return kind, true
		}
	}
	return qosMapKind{}, false
}

// The returned Desired owns only explicitly requested fields. Existing entries
// contribute to completeness/capability/runtime checks, but never to ownership.
func qosMerge(db vlanChangeDB, desired vlanChangeDB) (vlanChangeDB, error) {
	complete := vlanChangeDB{}
	for key, fields := range desired {
		complete[key] = maps.Clone(db[key])
		if complete[key] == nil {
			complete[key] = map[string]string{}
		}
		for field, value := range fields {
			if old, exists := complete[key][field]; exists && old != value {
				return nil, fmt.Errorf("conflicting QoS field %s/%s; replacement is outside additive scope", key, field)
			}
			complete[key][field] = value
		}
	}
	return complete, nil
}

func planNetworkQoSMap(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec qosMapSpec
	if err := routingDecode(r, "QoSMap", &spec, "name type entries"); err != nil {
		return nil, err
	}
	if err := qosMeta(spec.routingSpecMeta); err != nil {
		return nil, err
	}
	kind, ok := qosMapKinds[spec.Type]
	if !ok || !qosNamePattern.MatchString(spec.Name) || len(spec.Entries) == 0 {
		return nil, fmt.Errorf("valid map type, native name and nonempty entries required")
	}
	fields := map[string]string{}
	for _, raw := range spec.Entries {
		var entry struct {
			From *uint32 `json:"from"`
			To   *uint32 `json:"to"`
		}
		if err := routingDecode(qosNestedRequest(raw), "QoSEntry", &entry, "from to"); err != nil {
			return nil, err
		}
		if entry.From == nil || entry.To == nil {
			return nil, fmt.Errorf("map entries require from and to")
		}
		from := qosUint(uint64(*entry.From))
		if _, exists := fields[from]; exists {
			return nil, fmt.Errorf("duplicate map input")
		}
		fields[from] = qosUint(uint64(*entry.To))
	}
	desired := vlanChangeDB{kind.table + "|" + spec.Name: fields}
	complete, err := qosMerge(db, desired)
	if err != nil {
		return nil, err
	}
	if err := qosValidateMap(kind.table, complete[kind.table+"|"+spec.Name]); err != nil {
		return nil, err
	}
	if spec.Type == "TCToPriorityGroup" {
		return bufferPlan("QoSMap|"+spec.Type+"|"+spec.Name, desired), nil
	}
	return qosProfilePlan("QoSMap|"+spec.Type+"|"+spec.Name, desired), nil
}

func qosNestedRequest(raw json.RawMessage) *agent.NetworkRequest {
	return &agent.NetworkRequest{Kind: "QoSEntry", Spec: raw}
}

func qosValidateMap(table string, fields map[string]string) error {
	if len(fields) == 0 {
		return fmt.Errorf("empty QoS map")
	}
	// Installed sonic-types.yang tc_type is 0..15; TC_TO_QUEUE_MAP qindex
	// is one decimal digit. These are schema ceilings, NOT device capabilities.
	max, outputMax := uint64(15), uint64(15)
	switch table {
	case "DSCP_TO_TC_MAP":
		max = 63
	case "DOT1P_TO_TC_MAP":
		max = 7
	case "TC_TO_QUEUE_MAP":
		outputMax = 9
	case "TC_TO_PRIORITY_GROUP_MAP":
		outputMax = 7
	default:
		return fmt.Errorf("unsupported QoS map table")
	}
	for from, to := range fields {
		if _, err := qosNumber(from, max); err != nil {
			return fmt.Errorf("invalid QoS map input")
		}
		if _, err := qosNumber(to, outputMax); err != nil {
			return fmt.Errorf("invalid QoS map output")
		}
	}
	return nil
}

func planNetworkScheduler(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec qosSchedulerSpec
	if err := routingDecode(r, "Scheduler", &spec, "name algorithm weight meterType committedRate peakRate committedBurst peakBurst"); err != nil {
		return nil, err
	}
	if err := qosMeta(spec.routingSpecMeta); err != nil {
		return nil, err
	}
	if !qosNamePattern.MatchString(spec.Name) {
		return nil, fmt.Errorf("invalid scheduler name")
	}
	if spec.MeterType == "" {
		spec.MeterType = "Bytes"
	}
	if spec.MeterType != "Bytes" && spec.MeterType != "Packets" {
		return nil, fmt.Errorf("meterType must be Bytes or Packets")
	}
	fields := map[string]string{"type": spec.Algorithm, "meter_type": strings.ToLower(spec.MeterType)}
	if spec.Weight != nil {
		fields["weight"] = qosUint(uint64(*spec.Weight))
	}
	for field, value := range map[string]*uint64{"cir": spec.CommittedRate, "pir": spec.PeakRate, "cbs": spec.CommittedBurst, "pbs": spec.PeakBurst} {
		if value != nil {
			fields[field] = qosUint(*value)
		}
	}
	// Validate the explicit spec as well as merged configuration (an existing
	// weight must not silently satisfy a missing required weight in a weighted CR).
	if err := qosValidateScheduler(fields); err != nil {
		return nil, err
	}
	desired := vlanChangeDB{"SCHEDULER|" + spec.Name: fields}
	complete, err := qosMerge(db, desired)
	if err != nil {
		return nil, err
	}
	if err := qosValidateScheduler(complete["SCHEDULER|"+spec.Name]); err != nil {
		return nil, err
	}
	return qosProfilePlan("Scheduler|"+spec.Name, desired), nil
}

func qosValidateScheduler(fields map[string]string) error {
	if fields["type"] != "STRICT" && fields["type"] != "WRR" && fields["type"] != "DWRR" {
		return fmt.Errorf("scheduler algorithm must be STRICT, WRR or DWRR")
	}
	if fields["meter_type"] != "bytes" && fields["meter_type"] != "packets" {
		return fmt.Errorf("explicit scheduler meter_type required for applied proof")
	}
	_, weight := fields["weight"]
	if (fields["type"] == "STRICT") == weight {
		return fmt.Errorf("weighted scheduler requires weight; STRICT forbids weight")
	}
	for field, value := range fields {
		if field == "type" || field == "meter_type" {
			continue
		}
		max := uint64(math.MaxInt64)
		switch field {
		case "weight":
			max = 100
		case "cbs", "pbs":
			max = math.MaxUint32
		case "cir", "pir":
		default:
			return fmt.Errorf("unconsumed scheduler field %s", field)
		}
		n, err := qosNumber(value, max)
		if err != nil || n == 0 {
			return fmt.Errorf("scheduler %s must be positive and within native range", field)
		}
	}
	for field, dependency := range map[string]string{"pir": "cir", "cbs": "cir", "pbs": "pir"} {
		if fields[field] != "" && fields[dependency] == "" {
			return fmt.Errorf("%s requires %s", field, dependency)
		}
	}
	for high, low := range map[string]string{"pir": "cir", "pbs": "cbs"} {
		hi, _ := strconv.ParseUint(fields[high], 10, 64)
		lo, _ := strconv.ParseUint(fields[low], 10, 64)
		if fields[high] != "" && hi < lo {
			return fmt.Errorf("%s must be >= %s", high, low)
		}
	}
	return nil
}

func planNetworkQoSBinding(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec qosBindingSpec
	if err := routingDecode(r, "QoSBinding", &spec, "interfaceName dscpToTC dot1pToTC tcToQueue tcToPriorityGroup queues"); err != nil {
		return nil, err
	}
	if err := qosMeta(spec.routingSpecMeta); err != nil {
		return nil, err
	}
	port := spec.InterfaceName
	if !qosPortPattern.MatchString(port) {
		return nil, fmt.Errorf("QoSBinding requires canonical physical Ethernet name")
	}
	if _, err := qosNumber(strings.TrimPrefix(port, "Ethernet"), math.MaxUint32); err != nil {
		return nil, err
	}
	if len(db["PORT|"+port]) == 0 {
		return nil, fmt.Errorf("physical port does not exist")
	}
	if db["DEVICE_METADATA|localhost"]["switch_type"] == "voq" {
		return nil, fmt.Errorf("VOQ binding is unsupported")
	}
	desired := vlanChangeDB{}
	for typ, name := range map[string]string{"DSCPToTC": spec.DSCPToTC, "Dot1pToTC": spec.Dot1pToTC, "TCToQueue": spec.TCToQueue, "TCToPriorityGroup": spec.TCToPriorityGroup} {
		if name == "" {
			continue
		}
		kind := qosMapKinds[typ]
		if !qosNamePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid native map reference")
		}
		if err := qosValidateMap(kind.table, db[kind.table+"|"+name]); err != nil {
			return nil, fmt.Errorf("referenced map %s: %w", name, err)
		}
		key := "PORT_QOS_MAP|" + port
		if desired[key] == nil {
			desired[key] = map[string]string{}
		}
		desired[key][kind.field] = name
	}
	for _, raw := range spec.Queues {
		var queue struct {
			Index     *uint32 `json:"index"`
			Scheduler string  `json:"scheduler"`
		}
		if err := routingDecode(qosNestedRequest(raw), "QoSEntry", &queue, "index scheduler"); err != nil {
			return nil, err
		}
		if queue.Index == nil || !qosNamePattern.MatchString(queue.Scheduler) {
			return nil, fmt.Errorf("queue index and native scheduler required")
		}
		if err := qosValidateScheduler(db["SCHEDULER|"+queue.Scheduler]); err != nil {
			return nil, fmt.Errorf("referenced scheduler %s: %w", queue.Scheduler, err)
		}
		key := "QUEUE|" + port + "|" + qosUint(uint64(*queue.Index))
		if desired[key] != nil {
			return nil, fmt.Errorf("duplicate queue index")
		}
		desired[key] = map[string]string{"scheduler": queue.Scheduler}
	}
	if len(desired) == 0 {
		return nil, fmt.Errorf("at least one QoS binding required")
	}
	if _, err := qosMerge(db, desired); err != nil {
		return nil, err
	}
	if err := qosBindingSelectors(db, desired, port); err != nil {
		return nil, err
	}
	if len(desired) == 1 && len(desired["PORT_QOS_MAP|"+port]) == 1 && desired["PORT_QOS_MAP|"+port]["tc_to_pg_map"] != "" {
		return bufferPlan("QoSBinding|"+port, desired), nil
	}
	return qosBindingPlan(port, desired), nil
}

// A grouped selector is a separate Redis key but controls the same hardware.
// Reject overlapping scheduler ownership even when the current value matches.
func qosBindingSelectors(db, desired vlanChangeDB, port string) error {
	for key, fields := range db {
		parts := strings.Split(key, "|")
		if parts[0] != "QUEUE" && parts[0] != "PORT_QOS_MAP" {
			continue
		}
		if len(parts) < 2 {
			return fmt.Errorf("malformed native QoS selector")
		}
		selected := false
		for _, p := range strings.Split(parts[1], ",") {
			selected = selected || p == port
		}
		if !selected {
			continue
		}
		if parts[0] == "PORT_QOS_MAP" {
			if desired["PORT_QOS_MAP|"+port] != nil && key != "PORT_QOS_MAP|"+port {
				return fmt.Errorf("grouped port QoS selector overlaps binding")
			}
			continue
		}
		if fields["scheduler"] == "" {
			continue
		}
		if len(parts) != 3 {
			return fmt.Errorf("unsupported queue selector")
		}
		loText, hiText, ranged := strings.Cut(parts[2], "-")
		if !ranged {
			hiText = loText
		}
		lo, e1 := qosNumber(loText, math.MaxUint32)
		hi, e2 := qosNumber(hiText, math.MaxUint32)
		if e1 != nil || e2 != nil || lo > hi {
			return fmt.Errorf("invalid native queue range")
		}
		for target := range desired {
			if !strings.HasPrefix(target, "QUEUE|"+port+"|") || target == key {
				continue
			}
			n, _ := strconv.ParseUint(strings.TrimPrefix(target, "QUEUE|"+port+"|"), 10, 32)
			if n >= lo && n <= hi {
				return fmt.Errorf("native queue scheduler selector overlaps binding")
			}
		}
	}
	return nil
}
