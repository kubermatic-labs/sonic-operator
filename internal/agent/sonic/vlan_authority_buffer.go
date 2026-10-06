// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"strconv"
	"strings"
)

// vlanAuthorityBufferDependency recognizes the physical-port buffer/TC→PG
// bindings observed on the fleet. Native sonic-buffer-{pg,queue,profile,pool},
// sonic-port-qos-map and sonic-tc-priority-group-map YANG define these as port
// and buffer/map references, independent of VLAN membership. This is deliberately
// a subset: grouped/VOQ keys, NULL profiles and other QoS fields need separate
// qualification. It permits coexistence, never writes or claims buffer ownership.
func vlanAuthorityBufferDependency(db vlanChangeDB, key string, fields map[string]string) error {
	parts := strings.Split(key, "|")
	if len(parts) < 2 {
		return fmt.Errorf("malformed buffer/QoS binding")
	}
	if _, valid := ethernetNumber(parts[1]); !valid || db["PORT|"+parts[1]] == nil {
		return fmt.Errorf("buffer/QoS binding requires an existing canonical physical port")
	}
	if parts[0] == "PORT_QOS_MAP" {
		if len(parts) != 2 || len(fields) != 1 || !qosNamePattern.MatchString(fields["tc_to_pg_map"]) {
			return fmt.Errorf("unsupported PORT_QOS_MAP binding grammar or fields")
		}
		mapping := db["TC_TO_PRIORITY_GROUP_MAP|"+fields["tc_to_pg_map"]]
		if len(mapping) == 0 {
			return fmt.Errorf("missing TC_TO_PRIORITY_GROUP_MAP")
		}
		for tc, pg := range mapping {
			if !vlanAuthorityBufferUint(tc, 15) || !vlanAuthorityBufferUint(pg, 7) {
				return fmt.Errorf("invalid TC_TO_PRIORITY_GROUP_MAP entry")
			}
		}
		return nil
	}
	maxIndex, direction := uint64(7), "ingress"
	switch parts[0] {
	case "BUFFER_PG":
	case "BUFFER_QUEUE":
		if db["DEVICE_METADATA|localhost"]["switch_type"] == "voq" {
			return fmt.Errorf("VOQ buffer bindings not qualified for VLAN authority")
		}
		maxIndex, direction = 15, "egress"
	default:
		return fmt.Errorf("unsupported buffer/QoS dependency table")
	}
	if len(parts) != 3 || len(fields) != 1 || !vlanAuthorityBufferName(fields["profile"]) {
		return fmt.Errorf("unsupported buffer binding grammar or fields")
	}
	indices := strings.Split(parts[2], "-")
	if len(indices) > 2 || !vlanAuthorityBufferUint(indices[0], maxIndex) {
		return fmt.Errorf("invalid buffer binding index")
	}
	if len(indices) == 2 {
		if !vlanAuthorityBufferUint(indices[1], maxIndex) {
			return fmt.Errorf("invalid buffer binding range")
		}
		start, _ := strconv.Atoi(indices[0])
		end, _ := strconv.Atoi(indices[1])
		if start > end {
			return fmt.Errorf("reversed buffer binding range")
		}
	}
	profile := db["BUFFER_PROFILE|"+fields["profile"]]
	if len(profile) != 3 || !vlanAuthorityBufferName(profile["pool"]) || !vlanAuthorityBufferUint(profile["size"], ^uint64(0)) {
		return fmt.Errorf("missing or unsupported BUFFER_PROFILE")
	}
	pool := db["BUFFER_POOL|"+profile["pool"]]
	if pool["type"] != direction || !vlanAuthorityBufferUint(pool["size"], ^uint64(0)) {
		return fmt.Errorf("missing, invalid or wrong-direction BUFFER_POOL")
	}
	for field, value := range pool {
		switch field {
		case "type", "mode", "size":
		case "xoff":
			if !vlanAuthorityBufferUint(value, ^uint64(0)) {
				return fmt.Errorf("invalid BUFFER_POOL xoff")
			}
		default:
			return fmt.Errorf("unsupported BUFFER_POOL field")
		}
	}
	switch pool["mode"] {
	case "static":
		if !vlanAuthorityBufferUint(profile["static_th"], ^uint64(0)) {
			return fmt.Errorf("missing or invalid buffer static threshold")
		}
	case "dynamic":
		value := profile["dynamic_th"]
		n, err := strconv.ParseInt(value, 10, 32)
		if err != nil || n < -8 || n > 7 || strconv.FormatInt(n, 10) != value {
			return fmt.Errorf("missing or invalid buffer dynamic threshold")
		}
	default:
		return fmt.Errorf("unsupported BUFFER_POOL mode")
	}
	return nil
}

func vlanAuthorityBufferName(name string) bool {
	return len(name) <= 128 && name != "NULL" && vlanAuthorityLoggerName.MatchString(name)
}

func vlanAuthorityBufferUint(value string, max uint64) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n <= max && strconv.FormatUint(n, 10) == value
}
