// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const evpnASICPrefix = "ASIC_STATE:SAI_OBJECT_TYPE_"

// Name -> consumer OID -> SAI attributes -> translated hardware RID, including
// the term object pointing back at that exact tunnel. Similar ASIC content for
// a different tunnel never counts as this resource's runtime or capability.
func evpnTunnelASIC(ctx context.Context, read qosRead, name, source string) (string, map[string]string, error) {
	names, err := read.hash(ctx, "COUNTERS_DB", "COUNTERS_TUNNEL_NAME_MAP")
	if err != nil {
		return "", nil, err
	}
	oid := names[name]
	if !qosValidOID(oid) {
		return "", nil, nil
	}
	for other, id := range names {
		if other != name && id == oid {
			return "", nil, nil
		}
	}
	ok, err := qosTranslated(ctx, read, oid)
	if err != nil || !ok {
		return "", nil, err
	}
	attrs, err := read.hash(ctx, "ASIC_DB", evpnASICPrefix+"TUNNEL:"+oid)
	if err != nil {
		return "", nil, err
	}
	if attrs["SAI_TUNNEL_ATTR_TYPE"] != "SAI_TUNNEL_TYPE_VXLAN" || attrs["SAI_TUNNEL_ATTR_ENCAP_SRC_IP"] != source {
		return "", nil, nil
	}
	rif := attrs["SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE"]
	if !qosValidOID(rif) {
		return "", nil, nil
	}
	underlay, err := read.hash(ctx, "ASIC_DB", evpnASICPrefix+"ROUTER_INTERFACE:"+rif)
	if err != nil {
		return "", nil, err
	}
	ok, err = qosTranslated(ctx, read, rif)
	if err != nil || !ok {
		return "", nil, err
	}
	vr := underlay["SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID"]
	if !qosValidOID(vr) {
		return "", nil, nil
	}
	keys, err := read.keys(ctx, "ASIC_DB", evpnASICPrefix+"TUNNEL_TERM_TABLE_ENTRY:*")
	if err != nil {
		return "", nil, err
	}
	matches := 0
	for _, key := range keys {
		term, err := read.hash(ctx, "ASIC_DB", key)
		if err != nil {
			return "", nil, err
		}
		if term["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID"] != oid {
			continue
		}
		if term["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE"] != "SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP" || term["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE"] != "SAI_TUNNEL_TYPE_VXLAN" || term["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP"] != source || term["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID"] != vr {
			return "", nil, nil
		}
		ok, err := qosTranslated(ctx, read, strings.TrimPrefix(key, evpnASICPrefix+"TUNNEL_TERM_TABLE_ENTRY:"))
		if err != nil || !ok {
			return "", nil, err
		}
		matches++
	}
	if matches != 1 {
		return "", nil, nil
	}
	return oid, attrs, nil
}

func evpnOIDList(value string) ([]string, error) {
	count, rest, ok := strings.Cut(value, ":")
	n, err := strconv.ParseUint(count, 10, 8)
	if !ok || err != nil || n == 0 {
		return nil, fmt.Errorf("invalid SAI mapper list")
	}
	ids := strings.Split(rest, ",")
	if len(ids) != int(n) {
		return nil, fmt.Errorf("invalid SAI mapper count")
	}
	seen := map[string]bool{}
	for _, oid := range ids {
		if !qosValidOID(oid) || seen[oid] {
			return nil, fmt.Errorf("invalid or duplicate SAI mapper OID")
		}
		seen[oid] = true
	}
	return ids, nil
}

func evpnMapASIC(ctx context.Context, read qosRead, name, source string, vlan, vni uint32) (bool, error) {
	oid, attrs, err := evpnTunnelASIC(ctx, read, name, source)
	if err != nil || oid == "" {
		return false, err
	}
	mappers, err := evpnOIDList(attrs["SAI_TUNNEL_ATTR_DECAP_MAPPERS"])
	if err != nil {
		return false, nil
	}
	keys, err := read.keys(ctx, "ASIC_DB", evpnASICPrefix+"TUNNEL_MAP_ENTRY:*")
	if err != nil {
		return false, err
	}
	count := 0
	for _, key := range keys {
		entry, err := read.hash(ctx, "ASIC_DB", key)
		if err != nil {
			return false, err
		}
		mapper := entry["SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP"]
		if !slices.Contains(mappers, mapper) || entry["SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY"] != strconv.FormatUint(uint64(vni), 10) {
			continue
		}
		if entry["SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE"] != "SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID" || entry["SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE"] != strconv.FormatUint(uint64(vlan), 10) {
			return false, nil
		}
		mapping, err := read.hash(ctx, "ASIC_DB", evpnASICPrefix+"TUNNEL_MAP:"+mapper)
		if err != nil {
			return false, err
		}
		if mapping["SAI_TUNNEL_MAP_ATTR_TYPE"] != "SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID" {
			return false, nil
		}
		for _, id := range []string{mapper, strings.TrimPrefix(key, evpnASICPrefix+"TUNNEL_MAP_ENTRY:")} {
			ok, err := qosTranslated(ctx, read, id)
			if err != nil || !ok {
				return false, err
			}
		}
		count++
	}
	return count == 1, nil
}
