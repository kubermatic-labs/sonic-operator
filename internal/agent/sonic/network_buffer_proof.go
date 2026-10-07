// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// A qualification is collected from an existing native dependency graph before
// adoption. It is private journal data, never accepted in an API/RPC request.
// Repair can restore only Desired and only while all recorded native identities
// and non-owned dependencies remain unchanged.
type bufferNativeProof struct {
	Version     int                 `json:"version"`
	Desired     vlanChangeDB        `json:"desired"`
	Checks      []bufferNativeCheck `json:"checks"`
	Fingerprint string              `json:"fingerprint"`
}

type bufferNativeCheck struct {
	DB           string            `json:"db"`
	Key          string            `json:"key"`
	Fields       map[string]string `json:"fields"`
	Exact        bool              `json:"exact,omitempty"`
	Presence     bool              `json:"presence,omitempty"`
	RepairFields []string          `json:"repair_fields,omitempty"`
}

// A comparison difference is nonconvergence, not a transport/probe failure.
// It becomes repairable only if a fresh full repair preflight succeeds.
type bufferDifference struct{ DB, Key string }

func (e *bufferDifference) Error() string {
	return fmt.Sprintf("native buffer evidence differs at %s/%s", e.DB, e.Key)
}

func (p *bufferNativeProof) digest() string {
	copy := *p
	copy.Fingerprint = ""
	raw, _ := json.Marshal(copy)
	return vlanChangeHash(raw)
}

func (p *bufferNativeProof) validate(desired vlanChangeDB) error {
	if p == nil || p.Version != 2 || !reflect.DeepEqual(p.Desired, desired) || len(p.Checks) == 0 || len(p.Checks) > 4096 || !vlanAuthorityDigestValid(p.Fingerprint) || p.digest() != p.Fingerprint {
		return fmt.Errorf("invalid buffer native qualification fingerprint")
	}
	acknowledged := map[string]bool{}
	for _, c := range p.Checks {
		ack, err := c.validate(p.Desired)
		if err != nil {
			return err
		}
		if ack != "" {
			acknowledged[ack] = true
		}
	}
	for _, c := range p.Checks {
		if c.DB == "CONFIG_DB" && (strings.HasPrefix(c.Key, "BUFFER_POOL|") || strings.HasPrefix(c.Key, "BUFFER_PROFILE|") || strings.HasPrefix(c.Key, "TC_TO_PRIORITY_GROUP_MAP|")) && !acknowledged[c.Key] {
			return fmt.Errorf("missing independent consumer name/lifecycle evidence")
		}
	}
	return nil
}

func bufferProofKey(db, key string) bool {
	switch db {
	case "NATIVE":
		_, _, ok := bufferObjectKey(key)
		return key == "BUFFER_CONSUMER" || ok
	case "CONFIG_DB":
		if key == "DEVICE_METADATA|localhost" {
			return true
		}
		table, _, ok := strings.Cut(key, "|")
		return ok && slices.Contains([]string{"BUFFER_POOL", "BUFFER_PROFILE", "BUFFER_PG", "BUFFER_QUEUE", "PORT_QOS_MAP", "TC_TO_PRIORITY_GROUP_MAP"}, table)
	case "APPL_DB":
		table, _, ok := strings.Cut(key, ":")
		return ok && slices.Contains([]string{"BUFFER_POOL_TABLE", "BUFFER_PROFILE_TABLE", "BUFFER_PG_TABLE", "BUFFER_QUEUE_TABLE"}, table)
	case "COUNTERS_DB":
		return slices.Contains([]string{"COUNTERS_BUFFER_POOL_NAME_MAP", "COUNTERS_PORT_NAME_MAP", "COUNTERS_PG_NAME_MAP", "COUNTERS_PG_INDEX_MAP", "COUNTERS_PG_PORT_MAP", "COUNTERS_QUEUE_NAME_MAP", "COUNTERS_QUEUE_INDEX_MAP", "COUNTERS_QUEUE_PORT_MAP"}, key)
	case "STATE_DB":
		return key == "SWITCH_CAPABILITY|switch"
	case "ASIC_DB":
		if key == "VIDTORID" {
			return true
		}
		parts := strings.SplitN(key, ":", 3)
		return len(parts) == 3 && parts[0] == "ASIC_STATE" && slices.Contains([]string{"SAI_OBJECT_TYPE_BUFFER_POOL", "SAI_OBJECT_TYPE_BUFFER_PROFILE", "SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP", "SAI_OBJECT_TYPE_QUEUE", "SAI_OBJECT_TYPE_PORT", "SAI_OBJECT_TYPE_QOS_MAP"}, parts[1]) && qosValidOID(parts[2])
	}
	return false
}

func bufferProofKind(kind string, desired vlanChangeDB) bool {
	if validateNetworkFields(kind, desired) != nil {
		return false
	}
	switch kind {
	case "BufferPool", "BufferProfile", "BufferPG", "BufferQueue":
		return true
	case "QoSMap":
		for key := range desired {
			if !strings.HasPrefix(key, "TC_TO_PRIORITY_GROUP_MAP|") {
				return false
			}
		}
		return true
	case "QoSBinding":
		if len(desired) != 1 {
			return false
		}
		for key, fields := range desired {
			return strings.HasPrefix(key, "PORT_QOS_MAP|") && len(fields) == 1 && fields["tc_to_pg_map"] != ""
		}
	}
	return false
}

func bufferRepairField(db, key, field string, desired vlanChangeDB) bool {
	if db == "CONFIG_DB" {
		_, ok := desired[key][field]
		return ok
	}
	if db == "APPL_DB" {
		table, name, _ := strings.Cut(key, ":")
		_, ok := desired[strings.TrimSuffix(table, "_TABLE")+"|"+strings.ReplaceAll(name, ":", "|")][field]
		return ok
	}
	if db != "ASIC_DB" {
		return false
	}
	// Native create-only fields (pool/profile identity, direction and threshold
	// mode) are intentionally absent: restoring them requires object recreation.
	mapping := map[string][2]string{
		"SAI_BUFFER_POOL_ATTR_SIZE": {"BUFFER_POOL", "size"}, "SAI_BUFFER_POOL_ATTR_XOFF_SIZE": {"BUFFER_POOL", "xoff"},
		"SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE": {"BUFFER_PROFILE", "size"}, "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": {"BUFFER_PROFILE", "dynamic_th"}, "SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH": {"BUFFER_PROFILE", "static_th"},
		"SAI_BUFFER_PROFILE_ATTR_XON_TH": {"BUFFER_PROFILE", "xon"}, "SAI_BUFFER_PROFILE_ATTR_XOFF_TH": {"BUFFER_PROFILE", "xoff"}, "SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH": {"BUFFER_PROFILE", "xon_offset"},
		"SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE": {"BUFFER_PG", "profile"}, "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID": {"BUFFER_QUEUE", "profile"}, "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP": {"PORT_QOS_MAP", "tc_to_pg_map"}, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST": {"TC_TO_PRIORITY_GROUP_MAP", ""},
	}
	target, ok := mapping[field]
	if !ok {
		return false
	}
	for key, fields := range desired {
		if strings.HasPrefix(key, target[0]+"|") {
			if target[1] == "" {
				return true
			}
			if _, ok := fields[target[1]]; ok {
				return true
			}
		}
	}
	return false
}

// Normalize only documented zero-default buffer attributes. This lets an absent
// default be compared to explicit zero without masking nonzero unexpected state.
func bufferNormalize(key string, row map[string]string) map[string]string {
	out := maps.Clone(row)
	if out == nil {
		out = map[string]string{}
	}
	delete(out, "NULL")
	var defaults []string
	if strings.HasPrefix(key, "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:") {
		defaults = []string{"SAI_BUFFER_POOL_ATTR_XOFF_SIZE"}
	}
	if strings.HasPrefix(key, "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:") {
		defaults = []string{"SAI_BUFFER_PROFILE_ATTR_XON_TH", "SAI_BUFFER_PROFILE_ATTR_XOFF_TH", "SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH"}
	}
	if strings.HasPrefix(key, "ASIC_STATE:SAI_OBJECT_TYPE_PORT:") {
		for _, field := range bufferOtherPortMaps {
			if _, ok := out[field]; !ok {
				out[field] = "oid:0x0"
			}
		}
		defaults = []string{"SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"}
		if out["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE"] == "" {
			out["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE"] = "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED"
		}
	}
	for _, f := range defaults {
		if _, ok := out[f]; !ok {
			out[f] = "0"
		}
	}
	return out
}

func bufferVerify(ctx context.Context, read qosRead, p *bufferNativeProof, repair bool) error {
	if p == nil {
		return fmt.Errorf("missing native buffer qualification")
	}
	if err := p.validate(p.Desired); err != nil {
		return err
	}
	for _, c := range p.Checks {
		row, err := bufferReadHash(ctx, read, c.DB, c.Key)
		if err != nil {
			return err
		}
		if c.DB == "ASIC_DB" && len(row) == 0 {
			return fmt.Errorf("qualified native buffer object disappeared")
		}
		actual, err := bufferNormalizeChecked(c.Key, row)
		if err != nil {
			return err
		}
		want := maps.Clone(c.Fields)
		if repair {
			for _, f := range c.RepairFields {
				if f == bufferMapListAttr {
					actual[f], err = bufferUnownedTCEntries(actual[f], p.Desired)
					if err != nil {
						return err
					}
					want[f], err = bufferUnownedTCEntries(want[f], p.Desired)
					if err != nil {
						return err
					}
					continue
				}
				delete(actual, f)
				delete(want, f)
			}
		}
		if c.Exact && !reflect.DeepEqual(actual, want) {
			return &bufferDifference{DB: c.DB, Key: c.Key}
		}
		if !c.Exact && !networkSubset(vlanChangeDB{c.Key: actual}, vlanChangeDB{c.Key: want}) {
			return &bufferDifference{DB: c.DB, Key: c.Key}
		}
	}
	return nil
}

// validate checks one evidence entry. For an independent consumer
// acknowledgement it returns the acknowledged CONFIG_DB key.
func (c bufferNativeCheck) validate(desired vlanChangeDB) (string, error) {
	if !bufferProofKey(c.DB, c.Key) || (len(c.Fields) == 0 && !c.Presence) || len(c.Fields) > 512 || (c.Presence && (c.DB != "ASIC_DB" || len(c.RepairFields) > 0)) {
		return "", fmt.Errorf("invalid buffer native evidence target")
	}
	for _, field := range c.RepairFields {
		if _, ok := c.Fields[field]; !ok || !bufferRepairField(c.DB, c.Key, field, desired) {
			return "", fmt.Errorf("invalid buffer repair field")
		}
	}
	if c.DB != "NATIVE" {
		return "", nil
	}
	table, name, ok := bufferObjectKey(c.Key)
	if !ok {
		return "", nil
	}
	if !c.Exact || len(c.RepairFields) != 0 || len(c.Fields) != 3 || !qosValidOID(c.Fields["oid"]) || c.Fields["pending_remove"] != "false" || c.Fields["lifecycle"] == "" {
		return "", fmt.Errorf("invalid independent consumer acknowledgement")
	}
	return table + "|" + name, nil
}
