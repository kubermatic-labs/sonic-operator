// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"slices"
	"strings"
)

// Resolve the configured name independently, then compare every native port
// binding to that OID. A bound equal-valued map is not name proof. Each PG output must
// exist in the real port's COUNTERS name/index/port topology.
func (b *bufferDiscovery) qosMap(name, port string) error {
	consumerOID, err := b.namedObject("TC_TO_PRIORITY_GROUP_MAP", name)
	if err != nil {
		return err
	}
	key := "TC_TO_PRIORITY_GROUP_MAP|" + name
	fields := b.config[key]
	if err := qosValidateMap("TC_TO_PRIORITY_GROUP_MAP", fields); err != nil {
		return err
	}
	if err := b.configured(key); err != nil {
		return err
	}
	caps, err := b.read.hash(b.ctx, "STATE_DB", "SWITCH_CAPABILITY|switch")
	if err != nil {
		return err
	}
	tcField := "SWITCH|NUMBER_OF_TRAFFIC_CLASSES"
	count, err := qosNumber(caps[tcField], 256)
	if err != nil || count == 0 {
		return fmt.Errorf("native traffic-class count unavailable")
	}
	for from := range fields {
		n, _ := qosNumber(from, 15)
		if n >= count {
			return fmt.Errorf("TC-to-PG input exceeds native TC capability")
		}
	}
	if err := b.check("STATE_DB", "SWITCH_CAPABILITY|switch", map[string]string{tcField: caps[tcField]}, false, nil); err != nil {
		return err
	}
	ports := []string{}
	if port != "" {
		ports = append(ports, port)
	} else {
		for k, row := range b.config {
			if strings.HasPrefix(k, "PORT_QOS_MAP|") && row["tc_to_pg_map"] == name {
				ports = append(ports, strings.TrimPrefix(k, "PORT_QOS_MAP|"))
			}
		}
	}
	slices.Sort(ports)
	if len(ports) == 0 {
		return fmt.Errorf("TC-to-PG map requires an existing native port-binding anchor")
	}
	mapOID := consumerOID
	for _, port := range ports {
		oid, err := b.qosPort(port, name)
		if err != nil {
			return err
		}
		if oid != consumerOID {
			return fmt.Errorf("bound TC map OID disagrees with independent consumer name identity")
		}
		mapOID = oid
		seen := map[string]bool{}
		for _, index := range fields {
			if !seen[index] {
				if _, _, err := b.topology("BUFFER_PG", port, index); err != nil {
					return err
				}
				seen[index] = true
			}
		}
	}
	native := "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:" + mapOID
	attrs, err := b.read.hash(b.ctx, "ASIC_DB", native)
	if err != nil {
		return err
	}
	if !qosMapMatches(qosMapKinds["TCToPriorityGroup"], fields, attrs) {
		return fmt.Errorf("native TC-to-PG map attributes do not match the bound configuration")
	}
	repair := []string{}
	if len(b.proof.Desired[key]) > 0 {
		repair = append(repair, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST")
	}
	return b.check("ASIC_DB", native, attrs, true, repair)
}

func (b *bufferDiscovery) qosPort(port, name string) (string, error) {
	if !qosPortPattern.MatchString(port) {
		return "", fmt.Errorf("native QoS anchor requires canonical physical port")
	}
	key := "PORT_QOS_MAP|" + port
	if len(b.config[key]) != 1 {
		return "", fmt.Errorf("qualified port QoS row must contain only tc_to_pg_map; other whole-row effects are unqualified")
	}
	if b.config[key]["tc_to_pg_map"] != name {
		return "", fmt.Errorf("native TC-to-PG binding name differs")
	}
	if err := qosBindingSelectors(b.config, vlanChangeDB{key: {"tc_to_pg_map": name}}, port); err != nil {
		return "", err
	}
	if err := b.configured(key); err != nil {
		return "", err
	}
	names, err := b.read.hash(b.ctx, "COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
	if err != nil {
		return "", err
	}
	oid := names[port]
	if err := b.translated(oid); err != nil {
		return "", err
	}
	if err := b.check("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP", map[string]string{port: oid}, false, nil); err != nil {
		return "", err
	}
	native := "ASIC_STATE:SAI_OBJECT_TYPE_PORT:" + oid
	attrs, err := b.read.hash(b.ctx, "ASIC_DB", native)
	if err != nil {
		return "", err
	}
	attrs = bufferNormalize(native, attrs)
	if err := qosPreservePFC(b.config[key], attrs); err != nil {
		return "", err
	}
	attr := "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP"
	mapOID := attrs[attr]
	if err := b.translated(mapOID); err != nil {
		return "", err
	}
	want := map[string]string{attr: mapOID, "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL": attrs["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"], "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE": attrs["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE"]}
	for _, other := range bufferOtherPortMaps {
		want[other] = "oid:0x0"
	}
	repair := []string{}
	if _, ok := b.proof.Desired[key]["tc_to_pg_map"]; ok {
		repair = append(repair, attr)
	}
	if err := b.check("ASIC_DB", native, want, false, repair); err != nil {
		return "", err
	}
	return mapOID, nil
}
