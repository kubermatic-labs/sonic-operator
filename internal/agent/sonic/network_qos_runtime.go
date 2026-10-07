// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type qosRead interface {
	hash(context.Context, string, string) (map[string]string, error)
	keys(context.Context, string, string) ([]string, error)
	configSnapshot(context.Context) (vlanChangeDB, error)
}

var errQoSUnavailable = errors.New("QoS evidence unavailable")

type qosRedisRead struct{ agent *SonicAgent }

func (r qosRedisRead) configSnapshot(ctx context.Context) (vlanChangeDB, error) {
	db, _, err := r.agent.vlanChangeSnapshot(ctx)
	return db, err
}

func (r qosRedisRead) hash(ctx context.Context, db, key string) (map[string]string, error) {
	c, err := r.agent.Connect(db)
	if err != nil {
		return nil, err
	}
	fields, err := c.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("QoS read %s/%s: %w", db, key, err)
	}
	// HGETALL returns an empty map for notexists; WRONGTYPE/access/transport
	// failures remain errors, never mistaken for expected pre-creation absence.
	return fields, nil
}

func (r qosRedisRead) keys(ctx context.Context, db, pattern string) ([]string, error) {
	c, err := r.agent.Connect(db)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	iter := c.Scan(ctx, 0, pattern, 256).Iterator()
	for iter.Next(ctx) {
		seen[iter.Val()] = true
		if len(seen) > 16384 {
			return nil, fmt.Errorf("QoS evidence scan exceeds limit")
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

// Keep the interface private; production always uses the real Redis databases.
var _ qosRead = qosRedisRead{}

func qosCheckMapBounds(table string, fields, caps map[string]string) error {
	if err := qosValidateMap(table, fields); err != nil {
		return err
	}
	tcs, err := qosNumber(caps["SWITCH|NUMBER_OF_TRAFFIC_CLASSES"], 256)
	if err != nil || tcs == 0 {
		return fmt.Errorf("traffic-class capability is absent or invalid")
	}
	queues := uint64(0)
	if table == "TC_TO_QUEUE_MAP" {
		queues, err = qosNumber(caps["SWITCH|NUMBER_OF_UNICAST_QUEUES"], 256)
		if err != nil || queues == 0 {
			return fmt.Errorf("unicast-queue capability is absent or invalid")
		}
	}
	for from, to := range fields {
		f, _ := strconv.ParseUint(from, 10, 64)
		v, _ := strconv.ParseUint(to, 10, 64)
		if table == "TC_TO_QUEUE_MAP" {
			if f >= tcs || v >= queues {
				return fmt.Errorf("map exceeds actual TC/unicast-queue capability")
			}
		} else if v >= tcs {
			return fmt.Errorf("map exceeds actual traffic-class capability")
		}
	}
	return nil
}

func qosProfilePlan(identity string, desired vlanChangeDB) *networkPlan {
	p := &networkPlan{Identity: identity, Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		return qosProfilePreflight(ctx, qosRedisRead{m}, desired)
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return qosObserveProfile(ctx, qosRedisRead{m}, desired)
	}
	return p
}

func qosCompleteProfile(ctx context.Context, read qosRead, desired vlanChangeDB) (string, map[string]string, bool, error) {
	for key, fields := range desired { // Profile plans always contain one row.
		actual, err := read.hash(ctx, "CONFIG_DB", key)
		if err != nil {
			return "", nil, false, err
		}
		complete, err := qosMerge(vlanChangeDB{key: actual}, desired)
		if err != nil {
			return "", nil, false, err
		}
		return key, complete[key], networkSubset(vlanChangeDB{key: actual}, vlanChangeDB{key: fields}), nil
	}
	return "", nil, false, fmt.Errorf("empty profile")
}

func qosProfilePreflight(ctx context.Context, read qosRead, desired vlanChangeDB) error {
	key, fields, unchanged, err := qosCompleteProfile(ctx, read, desired)
	if err != nil {
		return err
	}
	table, _, _ := strings.Cut(key, "|")
	if table != "SCHEDULER" {
		caps, err := read.hash(ctx, "STATE_DB", "SWITCH_CAPABILITY|switch")
		if err != nil {
			return err
		}
		if err := qosCheckMapBounds(table, fields, caps); err != nil {
			return err
		}
		if unchanged {
			return nil
		}
		return qosProfileUnreferenced(ctx, read, key)
	}
	if err := qosValidateScheduler(fields); err != nil {
		return err
	}
	if unchanged {
		return nil
	}
	// Staging is intentionally separate from hardware acceptance. Never create
	// or extend a referenced scheduler: resolving a dangling native reference
	// would activate it without passing QoSBinding's applied-proof guard.
	if err := qosProfileUnreferenced(ctx, read, key); err != nil {
		return err
	}
	support, ok := read.(interface {
		schedulerStageSupport(context.Context, map[string]string) error
	})
	if !ok {
		return fmt.Errorf("scheduler staging consumer probe unavailable")
	}
	return support.schedulerStageSupport(ctx, fields)
}

func qosEvidence(ok bool, reason string, extra map[string]any, err error) (bool, json.RawMessage, error) {
	if extra == nil {
		extra = map[string]any{}
	}
	extra["applied"] = ok
	extra["reason"] = reason
	extra["source"] = "ASIC_DB attributes + VIDTORID (not a consumer name acknowledgement)"
	raw, _ := json.Marshal(extra)
	return ok, raw, err
}

func qosObserveProfile(ctx context.Context, read qosRead, desired vlanChangeDB) (bool, json.RawMessage, error) {
	key, fields, exists, err := qosCompleteProfile(ctx, read, desired)
	if err != nil {
		return qosEvidence(false, "profile read failed", nil, err)
	}
	if !exists {
		return qosEvidence(false, "profile configuration not present", nil, nil)
	}
	table, _, _ := strings.Cut(key, "|")
	if table != "SCHEDULER" {
		caps, err := read.hash(ctx, "STATE_DB", "SWITCH_CAPABILITY|switch")
		if err != nil {
			return qosEvidence(false, "capability read failed", nil, err)
		}
		if err := qosCheckMapBounds(table, fields, caps); err != nil {
			return qosEvidence(false, err.Error(), nil, nil)
		}
	}
	oid, err := qosCorrelateProfile(ctx, read, key, fields)
	if err != nil {
		return qosEvidence(false, "profile evidence read failed", nil, err)
	}
	if oid == "" {
		extra := map[string]any{"consumerNameOIDVerified": false}
		if table == "SCHEDULER" {
			extra["rateUnit"] = fields["meter_type"] + "/sec"
			extra["burstUnit"] = fields["meter_type"]
			extra["hardwareAcceptance"] = "unknown"
		}
		return qosEvidence(false, "consumer name-to-OID acknowledgement unavailable; matching ASIC content is insufficient", extra, nil)
	}
	units := map[string]any{"oid": oid, "correlation": "consumer name-to-OID acknowledgement"}
	if table == "SCHEDULER" {
		units["rateUnit"] = fields["meter_type"] + "/sec"
		units["burstUnit"] = fields["meter_type"]
	}
	return qosEvidence(true, "exact applied profile", units, nil)
}

func qosValidOID(oid string) bool {
	if !strings.HasPrefix(oid, "oid:0x") {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(oid, "oid:0x"), 16, 64)
	return err == nil && n != 0 && oid == fmt.Sprintf("oid:0x%x", n)
}

func qosTranslated(ctx context.Context, read qosRead, oid string) (bool, error) {
	if !qosValidOID(oid) {
		return false, nil
	}
	ids, err := read.hash(ctx, "ASIC_DB", "VIDTORID")
	if err != nil {
		return false, err
	}
	return qosValidOID(ids[oid]), nil
}

var qosSchedulerAttrs = map[string]string{
	"type": "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE", "weight": "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT", "meter_type": "SAI_SCHEDULER_ATTR_METER_TYPE",
	"cir": "SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE", "pir": "SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE",
	"cbs": "SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE", "pbs": "SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE",
}

func qosSchedulerMatches(fields, attrs map[string]string) bool {
	if qosValidateScheduler(fields) != nil {
		return false
	}
	for field, attr := range qosSchedulerAttrs {
		want := fields[field]
		switch field {
		case "type":
			want = "SAI_SCHEDULING_TYPE_" + want
		case "meter_type":
			want = "SAI_METER_TYPE_" + strings.ToUpper(want)
		default:
			if want == "" {
				// Absent SAI shaping fields have zero defaults. Nonzero extras
				// must not make an unshaped desired profile appear applied.
				if field == "weight" {
					if attrs[attr] != "" && attrs[attr] != "1" {
						return false
					}
					continue
				}
				if attrs[attr] != "" && attrs[attr] != "0" {
					return false
				}
				continue
			}
		}
		if attrs[attr] != want {
			return false
		}
	}
	return true
}

func qosMapMatches(kind qosMapKind, fields, attrs map[string]string) bool {
	if attrs["SAI_QOS_MAP_ATTR_TYPE"] != "SAI_QOS_MAP_TYPE_"+kind.sai {
		return false
	}
	// sairedis serializes sai_qos_map_list_t as {count,list:[{key,value}]}.
	var list struct {
		Count *uint32 `json:"count"`
		List  []struct {
			Key   map[string]json.RawMessage `json:"key"`
			Value map[string]json.RawMessage `json:"value"`
		} `json:"list"`
	}
	if json.Unmarshal([]byte(attrs["SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"]), &list) != nil || list.Count == nil || int(*list.Count) != len(list.List) || len(list.List) != len(fields) {
		return false
	}
	actual := map[string]string{}
	for _, entry := range list.List {
		from, ok1 := qosMapParameter(entry.Key, kind.from)
		to, ok2 := qosMapParameter(entry.Value, kind.to)
		if !ok1 || !ok2 {
			return false
		}
		// Other serialized union fields must be zero: no color/priority match
		// can be silently discarded when comparing the supported map types.
		if !qosZeroMapExtras(entry.Key, kind.from) || !qosZeroMapExtras(entry.Value, kind.to) {
			return false
		}
		key := qosUint(uint64(from))
		if _, exists := actual[key]; exists {
			return false
		}
		actual[key] = qosUint(uint64(to))
	}
	return reflect.DeepEqual(fields, actual)
}

func qosMapParameter(params map[string]json.RawMessage, name string) (uint32, bool) {
	raw, exists := params[name]
	var n uint32
	ok := exists && string(raw) != "null" && json.Unmarshal(raw, &n) == nil
	return n, ok
}

func qosZeroMapExtras(params map[string]json.RawMessage, selected string) bool {
	for name, raw := range params {
		if name == selected {
			continue
		}
		if name == "color" {
			var color string
			if json.Unmarshal(raw, &color) != nil || color != "SAI_PACKET_COLOR_GREEN" {
				return false
			}
			continue
		}
		if !strings.Contains(" tc dscp dot1p prio pg qidx mpls_exp fc ", " "+name+" ") {
			return false
		}
		n, ok := qosMapParameter(params, name)
		if !ok || n != 0 {
			return false
		}
	}
	return true
}

func qosMatchingObjects(ctx context.Context, read qosRead, table string, fields map[string]string) ([]string, error) {
	objectType := "QOS_MAP"
	kind, _ := qosMapDefinition(table)
	if table == "SCHEDULER" {
		objectType = "SCHEDULER"
	}
	prefix := "ASIC_STATE:SAI_OBJECT_TYPE_" + objectType + ":"
	keys, err := read.keys(ctx, "ASIC_DB", prefix+"*")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, key := range keys {
		attrs, err := read.hash(ctx, "ASIC_DB", key)
		if err != nil {
			return nil, err
		}
		matches := qosMapMatches(kind, fields, attrs)
		if table == "SCHEDULER" {
			matches = qosSchedulerMatches(fields, attrs)
		}
		if !matches {
			continue
		}
		oid := strings.TrimPrefix(key, prefix)
		applied, err := qosTranslated(ctx, read, oid)
		if err != nil {
			return nil, err
		}
		if applied {
			result = append(result, oid)
		}
	}
	return result, nil
}

// qosorch 202511 stores m_qos_maps[name].m_saiObjectId only in memory.
// Neither unique equal content nor an object appearing after CAS proves that
// the consumer created it for this name (stale objects/concurrent writers).
// VIDTORID proves translation, not config-name identity or attribute SET ack.
// Preflight/Runtime are read-only and there is no per-operation consumer token
// in networkPlan. A qos-runtime before/after journal would not fix causality.
// Until an actual consumer acknowledgement is available, retain probe errors
// but NEVER return an OID from a content comparison, including for bindings.
func qosCorrelateProfile(ctx context.Context, read qosRead, key string, fields map[string]string) (string, error) {
	table, _, _ := strings.Cut(key, "|")
	_, err := qosMatchingObjects(ctx, read, table, fields)
	return "", err
}

func qosBindingPlan(port string, desired vlanChangeDB) *networkPlan {
	p := &networkPlan{Identity: "QoSBinding|" + port, Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		_, _, err := qosBindingProof(ctx, qosRedisRead{m}, port, desired, false)
		return err
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return qosBindingProof(ctx, qosRedisRead{m}, port, desired, true)
	}
	return p
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func qosBindingProof(ctx context.Context, read qosRead, port string, desired vlanChangeDB, runtime bool) (bool, json.RawMessage, error) {
	fail := func(reason string, err error) (bool, json.RawMessage, error) {
		if errors.Is(err, errQoSUnavailable) {
			err = nil
		}
		if !runtime && err == nil {
			err = fmt.Errorf("QoS binding preflight: %s", reason)
		}
		return qosEvidence(false, reason, nil, err)
	}
	config := vlanChangeDB{}
	for _, pattern := range []string{"PORT|" + port, "DEVICE_METADATA|localhost", "PORT_QOS_MAP|*", "QUEUE|*"} {
		keys, err := read.keys(ctx, "CONFIG_DB", pattern)
		if err != nil {
			return fail("configuration read failed", err)
		}
		for _, key := range keys {
			config[key], err = read.hash(ctx, "CONFIG_DB", key)
			if err != nil {
				return fail("configuration read failed", err)
			}
		}
	}
	if len(config["PORT|"+port]) == 0 || config["DEVICE_METADATA|localhost"]["switch_type"] == "voq" {
		return fail("existing physical non-VOQ port required", nil)
	}
	if err := qosBindingSelectors(config, desired, port); err != nil {
		return fail(err.Error(), nil)
	}
	if _, err := qosMerge(config, desired); err != nil {
		return fail(err.Error(), nil)
	}
	if runtime && !networkSubset(config, desired) {
		return fail("binding configuration not present", nil)
	}
	ports, err := read.hash(ctx, "COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
	if err != nil {
		return fail("port OID read failed", err)
	}
	portOID := ports[port]
	applied, err := qosTranslated(ctx, read, portOID)
	if err != nil || !applied {
		return fail("physical port has no applied OID", err)
	}
	portAttrs, err := read.hash(ctx, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+portOID)
	if err != nil {
		return fail("port attributes read failed", err)
	}
	if len(portAttrs) == 0 {
		return fail("physical SAI port absent", nil)
	}
	caps, err := read.hash(ctx, "STATE_DB", "SWITCH_CAPABILITY|switch")
	if err != nil {
		return fail("capability read failed", err)
	}
	proof := map[string]any{"portOID": portOID}
	for key, fields := range desired {
		for field, name := range fields {
			table, saiAttr := "SCHEDULER", ""
			for _, kind := range qosMapKinds {
				if field == kind.field {
					table = kind.table
					saiAttr = "SAI_PORT_ATTR_QOS_" + kind.sai + "_MAP"
				}
			}
			profileKey := table + "|" + name
			profile, err := read.hash(ctx, "CONFIG_DB", profileKey)
			if err != nil {
				return fail("referenced profile read failed", err)
			}
			if table == "SCHEDULER" {
				err = qosValidateScheduler(profile)
			} else {
				err = qosCheckMapBounds(table, profile, caps)
			}
			if err != nil {
				return fail("referenced profile incomplete or unsupported: "+err.Error(), nil)
			}
			oid, err := qosCorrelateProfile(ctx, read, profileKey, profile)
			if err != nil || oid == "" {
				return fail("referenced profile lacks causal consumer name-to-OID acknowledgement", err)
			}
			proof[profileKey] = oid
			if table != "SCHEDULER" {
				if err := qosPreservePFC(config["PORT_QOS_MAP|"+port], portAttrs); err != nil {
					return fail(err.Error(), nil)
				}
				if runtime && portAttrs[saiAttr] != oid {
					return fail("port map OID is not applied", nil)
				}
				if table == "TC_TO_QUEUE_MAP" {
					for _, index := range profile {
						if _, err := qosQueueOID(ctx, read, port, portOID, index, caps); err != nil {
							return fail(err.Error(), err)
						}
					}
				}
				continue
			}
			index := strings.TrimPrefix(key, "QUEUE|"+port+"|")
			queueOID, err := qosQueueOID(ctx, read, port, portOID, index, caps)
			if err != nil {
				return fail(err.Error(), err)
			}
			group, attrs, err := qosQueueGroup(ctx, read, portOID, queueOID)
			if err != nil || group == "" {
				return fail("queue scheduler-group topology cannot be proven exclusive", err)
			}
			proof[key] = group
			if runtime && attrs["SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID"] != oid {
				return fail("scheduler-group profile OID is not applied", nil)
			}
		}
	}
	// Re-read requested rows/dependencies through CAS's CONFIG_DB snapshot in
	// the core engine; runtime also refuses config changes during these probes.
	for key, fields := range desired {
		row, err := read.hash(ctx, "CONFIG_DB", key)
		if err != nil {
			return fail("binding recheck failed", err)
		}
		if runtime && !networkSubset(vlanChangeDB{key: row}, vlanChangeDB{key: fields}) {
			return fail("binding changed during observation", nil)
		}
	}
	return qosEvidence(true, "exact applied profiles and exclusive binding topology", proof, nil)
}

func qosPreservePFC(config, attrs map[string]string) error {
	// qosorch defaults pfc_enable to zero on PORT_QOS_MAP SET. Full-hash
	// consumer notifications preserve configured fields; absent fields require
	// explicit zero runtime evidence, or we could disable out-of-band PFC.
	if mode := attrs["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE"]; mode != "" && mode != "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED" {
		return fmt.Errorf("asymmetric PFC preservation is not proven")
	}
	mask := uint64(0)
	if config["pfc_enable"] != "" {
		seen := map[uint64]bool{}
		for _, index := range strings.Split(config["pfc_enable"], ",") {
			n, err := qosNumber(index, 7)
			if err != nil || seen[n] {
				return fmt.Errorf("invalid native pfc_enable")
			}
			seen[n] = true
			mask |= 1 << n
		}
	}
	if attrs["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"] != qosUint(mask) {
		return fmt.Errorf("cannot prove PORT_QOS_MAP update preserves PFC; native pfc_enable and SAI bitmask must match")
	}
	return nil
}

func qosQueueOID(ctx context.Context, read qosRead, port, portOID, index string, caps map[string]string) (string, error) {
	count, err := qosNumber(caps["SWITCH|NUMBER_OF_UNICAST_QUEUES"], 256)
	n, numErr := qosNumber(index, 255)
	if err != nil || numErr != nil || count == 0 || n >= count {
		return "", fmt.Errorf("%w: queue exceeds actual unicast capability", errQoSUnavailable)
	}
	queues, err := read.hash(ctx, "COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
	if err != nil {
		return "", err
	}
	oid := queues[port+":"+index]
	ok, err := qosTranslated(ctx, read, oid)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: queue OID missing or untranslated", errQoSUnavailable)
	}
	attrs, err := read.hash(ctx, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:"+oid)
	if err != nil {
		return "", err
	}
	if attrs["SAI_QUEUE_ATTR_TYPE"] != "SAI_QUEUE_TYPE_UNICAST" || attrs["SAI_QUEUE_ATTR_INDEX"] != index {
		return "", fmt.Errorf("%w: queue OID type/index mismatch", errQoSUnavailable)
	}
	if owner := attrs["SAI_QUEUE_ATTR_PORT"]; owner != "" && owner != portOID {
		return "", fmt.Errorf("%w: queue OID belongs to another port", errQoSUnavailable)
	}
	return oid, nil
}

func qosObjectList(value string) ([]string, bool) {
	count, rest, ok := strings.Cut(value, ":")
	n, err := qosNumber(count, 16384)
	if !ok || err != nil || n == 0 {
		return nil, false
	}
	list := strings.Split(rest, ",")
	if uint64(len(list)) != n {
		return nil, false
	}
	seen := map[string]bool{}
	for _, oid := range list {
		if !qosValidOID(oid) || seen[oid] {
			return nil, false
		}
		seen[oid] = true
	}
	return list, true
}

func qosQueueGroup(ctx context.Context, read qosRead, portOID, queueOID string) (string, map[string]string, error) {
	port, err := read.hash(ctx, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+portOID)
	if err != nil {
		return "", nil, err
	}
	groups, ok := qosObjectList(port["SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST"])
	if !ok {
		return "", nil, nil
	}
	var found string
	var result map[string]string
	for _, group := range groups {
		attrs, err := read.hash(ctx, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER_GROUP:"+group)
		if err != nil {
			return "", nil, err
		}
		children, ok := qosObjectList(attrs["SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST"])
		if !ok {
			continue
		}
		for _, child := range children {
			if child != queueOID {
				continue
			}
			// qosorch writes this group's scheduler. Any sibling queue/group
			// would also change scheduling, violating queue-specific ownership.
			if found != "" || len(children) != 1 || attrs["SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT"] != "1" || attrs["SAI_SCHEDULER_GROUP_ATTR_PORT_ID"] != portOID {
				return "", nil, nil
			}
			translated, err := qosTranslated(ctx, read, group)
			if err != nil || !translated {
				return "", nil, err
			}
			found, result = group, maps.Clone(attrs)
		}
	}
	return found, result, nil
}
