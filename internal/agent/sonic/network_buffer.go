// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Buffer plans preserve native selector spelling and claim only explicit fields.
// Pool/profile definitions are typed generating inputs, never ASIC_DB writes.
func planNetworkBuffer(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec any
	var fields string
	switch r.Kind {
	case "BufferPool":
		spec = &api.SwitchBufferPoolSpec{}
		fields = "name type mode size xoff"
	case "BufferProfile":
		spec = &api.SwitchBufferProfileSpec{}
		fields = "name pool size dynamicThreshold staticThreshold xon xoff xonOffset"
	case "BufferPG":
		spec = &api.SwitchBufferPGSpec{}
		fields = "interfaceName range profile"
	case "BufferQueue":
		spec = &api.SwitchBufferQueueSpec{}
		fields = "interfaceName range profile"
	default:
		return nil, fmt.Errorf("unsupported buffer kind")
	}
	if err := routingDecode(r, r.Kind, spec, fields); err != nil {
		return nil, err
	}
	if _, err := api.ValidateBufferSpec(spec); err != nil {
		return nil, err
	}
	desired := vlanChangeDB{}
	put := func(row map[string]string, field string, v *uint64) {
		if v != nil {
			row[field] = qosUint(*v)
		}
	}
	switch s := spec.(type) {
	case *api.SwitchBufferPoolSpec:
		if err := bufferMeta(s.NetworkResourceSpec); err != nil {
			return nil, err
		}
		row := map[string]string{"type": s.Type, "mode": s.Mode, "size": qosUint(*s.Size)}
		put(row, "xoff", s.Xoff)
		desired["BUFFER_POOL|"+string(s.Name)] = row
	case *api.SwitchBufferProfileSpec:
		if err := bufferMeta(s.NetworkResourceSpec); err != nil {
			return nil, err
		}
		row := map[string]string{"pool": string(s.Pool), "size": qosUint(*s.Size)}
		put(row, "static_th", s.StaticThreshold)
		put(row, "xon", s.Xon)
		put(row, "xoff", s.Xoff)
		put(row, "xon_offset", s.XonOffset)
		if s.DynamicThreshold != nil {
			row["dynamic_th"] = strconv.FormatInt(int64(*s.DynamicThreshold), 10)
		}
		desired["BUFFER_PROFILE|"+string(s.Name)] = row
	case *api.SwitchBufferPGSpec:
		if err := bufferMeta(s.NetworkResourceSpec); err != nil {
			return nil, err
		}
		desired["BUFFER_PG|"+s.InterfaceName+"|"+s.Range] = map[string]string{"profile": string(s.Profile)}
	case *api.SwitchBufferQueueSpec:
		if err := bufferMeta(s.NetworkResourceSpec); err != nil {
			return nil, err
		}
		desired["BUFFER_QUEUE|"+s.InterfaceName+"|"+s.Range] = map[string]string{"profile": string(s.Profile)}
	}
	complete, err := qosMerge(db, desired)
	if err != nil {
		return nil, err
	}
	for key, row := range complete {
		table, name, _ := strings.Cut(key, "|")
		switch table {
		case "BUFFER_POOL":
			err = bufferValidatePool(row)
		case "BUFFER_PROFILE":
			err = bufferValidateProfile(db, row, "")
		default:
			port, _, _ := strings.Cut(name, "|")
			if len(db["PORT|"+port]) == 0 || db["DEVICE_METADATA|localhost"]["switch_type"] == "voq" {
				return nil, fmt.Errorf("buffer binding requires existing non-VOQ physical port")
			}
			direction := "ingress"
			if table == "BUFFER_QUEUE" {
				direction = "egress"
			}
			err = bufferValidateProfile(db, db["BUFFER_PROFILE|"+row["profile"]], direction)
			if err == nil {
				err = bufferSelectors(db, key)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	id, err := networkIdentity(r)
	if err != nil {
		return nil, err
	}
	return bufferPlan(id, desired), nil
}

func bufferMeta(s api.NetworkResourceSpec) error {
	if s.ManagementPolicy != "" && s.ManagementPolicy != api.NetworkManagementPolicyObserve && s.ManagementPolicy != api.NetworkManagementPolicyManage {
		return fmt.Errorf("invalid managementPolicy")
	}
	return nil
}

func bufferValidatePool(row map[string]string) error {
	if (row["type"] != "ingress" && row["type"] != "egress") || (row["mode"] != "static" && row["mode"] != "dynamic") {
		return fmt.Errorf("buffer pool missing or invalid direction/mode")
	}
	size, err := qosNumber(row["size"], math.MaxInt64)
	if err != nil || size == 0 {
		return fmt.Errorf("buffer pool requires positive size")
	}
	for field, value := range row {
		switch field {
		case "type", "mode", "size":
		case "xoff":
			n, err := qosNumber(value, math.MaxInt64)
			if err != nil || n > size || row["type"] != "ingress" {
				return fmt.Errorf("invalid pool headroom")
			}
		default:
			return fmt.Errorf("unqualified buffer pool field %s", field)
		}
	}
	return nil
}

func bufferValidateProfile(db vlanChangeDB, row map[string]string, direction string) error {
	pool := db["BUFFER_POOL|"+row["pool"]]
	if !qosNamePattern.MatchString(row["pool"]) {
		return fmt.Errorf("missing native buffer pool reference")
	}
	if err := bufferValidatePool(pool); err != nil {
		return err
	}
	if direction != "" && pool["type"] != direction {
		return fmt.Errorf("buffer binding direction does not match pool")
	}
	_, dynamic := row["dynamic_th"]
	_, static := row["static_th"]
	if dynamic == static || (dynamic && pool["mode"] != "dynamic") || (static && pool["mode"] != "static") {
		return fmt.Errorf("profile threshold must match pool mode")
	}
	if _, err := qosNumber(row["size"], math.MaxInt64); err != nil {
		return fmt.Errorf("profile requires reserved size")
	}
	for field, value := range row {
		switch field {
		case "pool":
		case "dynamic_th":
			n, err := strconv.ParseInt(value, 10, 32)
			if err != nil || n < -8 || n > 7 || strconv.FormatInt(n, 10) != value {
				return fmt.Errorf("invalid dynamic threshold")
			}
		case "size", "static_th", "xon", "xoff", "xon_offset":
			if _, err := qosNumber(value, math.MaxInt64); err != nil {
				return err
			}
			if (field == "xon" || field == "xoff" || field == "xon_offset") && pool["type"] != "ingress" {
				return fmt.Errorf("headroom fields require ingress profile")
			}
		default:
			return fmt.Errorf("unqualified buffer profile field %s", field)
		}
	}
	return nil
}

// Native comma-separated ports and inclusive ranges can alias independent Redis
// keys. Reject intersecting selectors even when their profile values are equal.
func bufferSelectors(db vlanChangeDB, target string) error {
	parts := strings.Split(target, "|")
	if len(parts) != 3 {
		return fmt.Errorf("invalid buffer selector")
	}
	max := uint64(7)
	if parts[0] == "BUFFER_QUEUE" {
		max = 255
	}
	lo, hi, err := api.BufferRange(parts[2], max)
	if err != nil {
		return err
	}
	for key := range db {
		other := strings.Split(key, "|")
		if other[0] != parts[0] || key == target {
			continue
		}
		if len(other) != 3 {
			return fmt.Errorf("malformed native buffer selector")
		}
		for _, port := range strings.Split(other[1], ",") {
			if port != parts[1] {
				continue
			}
			a, b, err := api.BufferRange(other[2], max)
			if err != nil {
				return err
			}
			if a <= hi && lo <= b {
				return fmt.Errorf("overlapping native buffer selector %s", key)
			}
		}
	}
	return nil
}

func networkBufferTarget(kind, table, name string) bool {
	switch kind {
	case "BufferPool":
		return table == "BUFFER_POOL" && qosNamePattern.MatchString(name)
	case "BufferProfile":
		return table == "BUFFER_PROFILE" && qosNamePattern.MatchString(name)
	case "BufferPG", "BufferQueue":
		want, max := "BUFFER_PG", uint64(7)
		if kind == "BufferQueue" {
			want, max = "BUFFER_QUEUE", 255
		}
		port, selector, ok := strings.Cut(name, "|")
		n, err := qosNumber(strings.TrimPrefix(port, "Ethernet"), math.MaxUint32)
		if !ok || table != want || err != nil || port != "Ethernet"+qosUint(n) {
			return false
		}
		_, _, err = api.BufferRange(selector, max)
		return err == nil
	default:
		return true
	}
}
