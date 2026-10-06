// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

type networkPortSpec struct {
	routingSpecMeta
	NativeName string  `json:"nativeName"`
	Handle     string  `json:"handle,omitempty"`
	AdminState string  `json:"adminState,omitempty"`
	Speed      *uint32 `json:"speed,omitempty"`
	MTU        *uint32 `json:"mtu,omitempty"`
	FEC        string  `json:"fec,omitempty"`
}

func networkPortLayout(db vlanChangeDB, p *networkPlan) string {
	key := "PORT|" + strings.TrimPrefix(p.Identity, "Port|")
	port := db[key]
	data, _ := json.Marshal(networkPortLayoutContext(port))
	return vlanChangeHash(data)
}

// Keep the stored layout fingerprint and saved-state evidence on exactly the
// same normalized fields. Absent native fields normalize to the empty string.
func networkPortLayoutContext(port map[string]string) map[string]string {
	return map[string]string{"lanes": port["lanes"], "index": port["index"], "subport": port["subport"], "autoneg": port["autoneg"], "macsec": port["macsec"]}
}

// Port support intentionally adopts a native value already qualified on this
// layout and repairs that value. New speeds/FEC modes require separate hardware
// qualification, not a guessed capability based on the numeric schema range.
func networkPortOwnership(db vlanChangeDB, p *networkPlan, r *networkRecord) error {
	if r != nil && r.PortLayout != networkPortLayout(db, p) {
		return fmt.Errorf("port layout changed since adoption")
	}
	for key, fields := range p.Desired {
		for field, value := range fields {
			if r != nil {
				if previous, exists := r.Fields[key][field]; exists {
					if previous != value {
						return fmt.Errorf("adopted port values are immutable; hardware qualification required")
					}
					continue
				}
			}
			if db[key][field] != value {
				return fmt.Errorf("port adoption requires an exactly matching existing native field")
			}
		}
	}
	return nil
}

func networkPortFields(key string, fields map[string]string) error {
	table, name, ok := strings.Cut(key, "|")
	if _, valid := ethernetNumber(name); !ok || table != "PORT" || !valid {
		return fmt.Errorf("invalid port target")
	}
	for field, value := range fields {
		switch field {
		case "speed":
			if value != "1000" && value != "10000" && value != "25000" && value != "100000" {
				return fmt.Errorf("invalid port speed field")
			}
		case "mtu":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || n < 1280 || n > 9216 || value != strconv.FormatUint(n, 10) {
				return fmt.Errorf("invalid port MTU field")
			}
		case "fec":
			if value != "none" && value != "rs" && value != "fc" {
				return fmt.Errorf("invalid port FEC field")
			}
		default:
			return fmt.Errorf("unsupported port field")
		}
	}
	return nil
}

func planNetworkPort(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s networkPortSpec
	if err := routingDecode(r, "Port", &s, "nativeName handle adminState speed mtu fec"); err != nil {
		return nil, err
	}
	if _, ok := ethernetNumber(s.NativeName); !ok {
		return nil, fmt.Errorf("canonical Ethernet port required")
	}
	key := "PORT|" + s.NativeName
	port := db[key]
	if len(port) == 0 {
		return nil, fmt.Errorf("physical port does not exist")
	}
	fields := map[string]string{}
	if s.Speed != nil {
		if *s.Speed != 1000 && *s.Speed != 10000 && *s.Speed != 25000 && *s.Speed != 100000 {
			return nil, fmt.Errorf("unsupported fleet port speed")
		}
		fields["speed"] = strconv.FormatUint(uint64(*s.Speed), 10)
	}
	if s.MTU != nil {
		if *s.MTU < 1280 || *s.MTU > 9216 {
			return nil, fmt.Errorf("MTU must be 1280..9216")
		}
		if port["macsec"] != "" {
			return nil, fmt.Errorf("MACsec MTU ownership is unsupported")
		}
		fields["mtu"] = strconv.FormatUint(uint64(*s.MTU), 10)
	}
	if s.FEC != "" {
		if s.FEC != "none" && s.FEC != "rs" && s.FEC != "fc" {
			return nil, fmt.Errorf("unsupported native FEC mode")
		}
		fields["fec"] = s.FEC
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("at least one port field required")
	}
	if (s.Speed != nil || s.FEC != "") && port["autoneg"] != "" && port["autoneg"] != "off" {
		return nil, fmt.Errorf("autonegotiated speed/FEC ownership is unsupported")
	}
	desired := vlanChangeDB{key: fields}
	return &networkPlan{Identity: "Port|" + s.NativeName, Desired: desired, Persisted: networkPortPersistence(desired, s.NativeName, networkPortLayoutContext(port)), Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return networkPortRuntime(ctx, s.NativeName, fields, (qosRedisRead{agent: m}).hash)
	}}, nil
}

type networkPortRead func(context.Context, string, string) (map[string]string, error)

// SONiC 202511 portmgr/portsorch consume PORT fields. SAI's MTU includes
// Ethernet header, FCS and VLAN tag (22 bytes). Carrier is separate evidence.
func networkPortRuntime(ctx context.Context, name string, want map[string]string, read networkPortRead) (bool, json.RawMessage, error) {
	app, err := read(ctx, "APPL_DB", "PORT_TABLE:"+name)
	if err != nil {
		return false, nil, err
	}
	ports, err := read(ctx, "COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
	if err != nil {
		return false, nil, err
	}
	oid := ports[name]
	applied, err := aclReadApplied(ctx, aclReader(read))
	if err != nil {
		return false, nil, err
	}
	if !applied.object(oid, "PORT") {
		return false, json.RawMessage(`{"asicPortResolved":false}`), nil
	}
	attrs, err := read(ctx, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+oid)
	if err != nil {
		return false, nil, err
	}
	matched := true
	for field, value := range want {
		matched = matched && app[field] == value
		switch field {
		case "speed":
			matched = matched && attrs["SAI_PORT_ATTR_SPEED"] == value
		case "mtu":
			mtu, _ := strconv.Atoi(value)
			matched = matched && attrs["SAI_PORT_ATTR_MTU"] == strconv.Itoa(mtu+22)
		case "fec":
			matched = matched && attrs["SAI_PORT_ATTR_FEC_MODE"] == map[string]string{"none": "SAI_PORT_FEC_MODE_NONE", "rs": "SAI_PORT_FEC_MODE_RS", "fc": "SAI_PORT_FEC_MODE_FC"}[value]
		default:
			return false, nil, fmt.Errorf("unsupported runtime port field")
		}
	}
	latest, err := read(ctx, "COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
	if err != nil {
		return false, nil, err
	}
	stable, err := applied.stable(ctx, aclReader(read))
	if err != nil {
		return false, nil, err
	}
	matched = matched && latest[name] == oid && stable
	// VIDTORID proves a live object identity, not an attribute-SET acknowledgment.
	observed, _ := json.Marshal(map[string]any{"name": name, "portFieldsMatch": matched, "carrier": app["oper_status"], "appliedIdentityStable": stable && latest[name] == oid, "attributeSetAcknowledged": false, "forwardingTested": false})
	return matched, observed, ctx.Err()
}
