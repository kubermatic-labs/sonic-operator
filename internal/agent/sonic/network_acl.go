// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Native consumer: sonic-swss 7917e3d7c70dfdde6a34c6f5886118dab316f187,
// orchagent/aclorch.cpp: initDefaultTableTypes, AclTable::validate,
// bindAclTable (empty ports succeeds), doAclTableTask (same type/stage updates
// bindings without recreating rules), registerFlexCounter and setAcl*Status.
// A policy intentionally NEVER owns ports@: the engine merges field owners.
var aclName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

const aclDefaultRule = "DEFAULT"

type aclRuleSpec struct {
	Name            string  `json:"name"`
	Priority        uint32  `json:"priority"`
	Action          string  `json:"action"`
	Source          string  `json:"source,omitempty"`
	Destination     string  `json:"destination,omitempty"`
	Protocol        *uint32 `json:"protocol,omitempty"`
	SourcePort      *uint32 `json:"sourcePort,omitempty"`
	DestinationPort *uint32 `json:"destinationPort,omitempty"`
}

type aclPolicySpec struct {
	lagL3Selectors
	Name          string        `json:"name"`
	Family        string        `json:"family"`
	DefaultAction string        `json:"defaultAction"`
	Rules         []aclRuleSpec `json:"rules,omitempty"`
}

type aclBindingSpec struct {
	lagL3Selectors
	Policy     string   `json:"policy"`
	Interfaces []string `json:"interfaces"`
}

// Validate exact JSON spelling recursively before the typed decoder, which
// otherwise accepts case aliases, duplicate keys and null numeric pointers.
func aclDecode(r *agent.NetworkRequest, kind string, out any) error {
	if err := agent.ValidateNetworkRequest(r, false); err != nil {
		return err
	}
	if r.Kind != kind {
		return fmt.Errorf("expected %s request", kind)
	}
	d := json.NewDecoder(bytes.NewReader(r.Spec))
	var value func() error
	value = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			return fmt.Errorf("null ACL spec field")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				tok, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := tok.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate ACL spec field")
				}
				seen[name] = true
				switch name {
				case "switchRef", "managementPolicy", "name", "family", "defaultAction", "rules", "priority", "action", "source", "destination", "protocol", "sourcePort", "destinationPort", "policy", "interfaces":
				default:
					return fmt.Errorf("unknown ACL spec field %q", name)
				}
			}
			if err := value(); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing ACL JSON")
	}
	d = json.NewDecoder(bytes.NewReader(r.Spec))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("invalid ACL spec: %w", err)
	}
	return nil
}

func aclAction(action string) (string, error) {
	switch action {
	case "Permit":
		return "FORWARD", nil
	case "Drop":
		return "DROP", nil
	default:
		return "", fmt.Errorf("ACL action must explicitly be Permit or Drop")
	}
}

func aclPolicyDesired(s aclPolicySpec) (vlanChangeDB, error) {
	if !aclName.MatchString(s.Name) {
		return nil, fmt.Errorf("invalid ACL policy name")
	}
	tableType, ipType := "L3", "IPV4ANY"
	if s.Family == "IPv6" {
		tableType, ipType = "L3V6", "IPV6ANY"
	} else if s.Family != "IPv4" {
		return nil, fmt.Errorf("ACL family must be IPv4 or IPv6")
	}
	defaultAction, err := aclAction(s.DefaultAction)
	if err != nil {
		return nil, err
	}
	if len(s.Rules) > 256 {
		return nil, fmt.Errorf("ACL rule limit exceeded")
	}
	desired := vlanChangeDB{
		"ACL_TABLE|" + s.Name:                       {"type": tableType, "stage": "INGRESS"},
		"ACL_RULE|" + s.Name + "|" + aclDefaultRule: {"PRIORITY": "1", "PACKET_ACTION": defaultAction, "IP_TYPE": ipType},
	}
	names, priorities := map[string]bool{aclDefaultRule: true}, map[uint32]bool{1: true}
	for _, rule := range s.Rules {
		if !aclName.MatchString(rule.Name) || names[rule.Name] || rule.Priority < 2 || rule.Priority > 999999 || priorities[rule.Priority] {
			return nil, fmt.Errorf("invalid or duplicate ACL rule name/priority")
		}
		names[rule.Name], priorities[rule.Priority] = true, true
		action, err := aclAction(rule.Action)
		if err != nil {
			return nil, err
		}
		fields := map[string]string{"PRIORITY": strconv.FormatUint(uint64(rule.Priority), 10), "PACKET_ACTION": action, "IP_TYPE": ipType}
		for field, cidr := range map[string]string{"SRC_IP": rule.Source, "DST_IP": rule.Destination} {
			if cidr == "" {
				continue
			}
			p, err := netip.ParsePrefix(cidr)
			if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Is4() != (s.Family == "IPv4") {
				return nil, fmt.Errorf("invalid ACL prefix/family")
			}
			if s.Family == "IPv6" {
				field += "V6"
			}
			fields[field] = p.String()
		}
		if rule.Protocol != nil {
			if *rule.Protocol < 1 || *rule.Protocol > 143 {
				return nil, fmt.Errorf("ACL protocol must be 1..143")
			}
			field := "IP_PROTOCOL"
			if s.Family == "IPv6" {
				field = "NEXT_HEADER"
			}
			fields[field] = strconv.FormatUint(uint64(*rule.Protocol), 10)
		}
		for field, port := range map[string]*uint32{"L4_SRC_PORT": rule.SourcePort, "L4_DST_PORT": rule.DestinationPort} {
			if port == nil {
				continue
			}
			if *port > 65535 || rule.Protocol == nil || (*rule.Protocol != 6 && *rule.Protocol != 17) {
				return nil, fmt.Errorf("ACL ports require TCP/UDP and range 0..65535")
			}
			fields[field] = strconv.FormatUint(uint64(*port), 10)
		}
		desired["ACL_RULE|"+s.Name+"|"+rule.Name] = fields
	}
	return desired, nil
}

func aclPolicyTarget(db vlanChangeDB, name string) vlanChangeDB {
	out := vlanChangeDB{}
	for key, fields := range db {
		if key == "ACL_TABLE|"+name || strings.HasPrefix(key, "ACL_RULE|"+name+"|") {
			out[key] = maps.Clone(fields)
			if key == "ACL_TABLE|"+name {
				delete(out[key], "ports@")
			}
		}
	}
	return out
}

func aclPolicyConfigSafe(db, desired vlanChangeDB, name string) error {
	if len(db["ACL_TABLE_TYPE|"+desired["ACL_TABLE|"+name]["type"]]) != 0 {
		return fmt.Errorf("custom override of built-in ACL table type is unsupported")
	}
	actual := aclPolicyTarget(db, name)
	// Never repair or extend an active policy: asynchronous SWSS rule processing
	// would expose a partially changed policy even when the Redis CAS is atomic.
	if db["ACL_TABLE|"+name]["ports@"] != "" && !reflect.DeepEqual(actual, desired) {
		return fmt.Errorf("bound ACL policy is immutable; partial policy or rule change rejected")
	}
	for key, fields := range actual {
		for field, value := range fields {
			if want, ok := desired[key][field]; !ok || value != want {
				return fmt.Errorf("ACL policy has conflicting or unsupported native fields")
			}
		}
	}
	return nil
}

func planNetworkACLPolicy(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s aclPolicySpec
	if err := aclDecode(r, "ACLPolicy", &s); err != nil {
		return nil, err
	}
	desired, err := aclPolicyDesired(s)
	if err != nil {
		return nil, err
	}
	if err := aclPolicyConfigSafe(db, desired, s.Name); err != nil {
		return nil, err
	}
	p := &networkPlan{Identity: "ACLPolicy|" + s.Name, Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		latest, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return err
		}
		if err := aclPolicyConfigSafe(latest, desired, s.Name); err != nil {
			return err
		}
		if !reflect.DeepEqual(aclPolicyTarget(latest, s.Name), desired) {
			if latest["ACL_TABLE|"+s.Name] != nil {
				previous, err := aclExistingPolicy(latest, s.Name)
				if err != nil {
					return fmt.Errorf("existing partial ACL table cannot be safely extended: %w", err)
				}
				ok, _, err := aclRuntime(ctx, s.Name, previous, nil, m.aclRead, m.aclScan)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("ACL extension requires completely applied unbound previous policy")
				}
			} else {
				state, err := m.aclRead(ctx, "STATE_DB", "ACL_TABLE_TABLE|"+s.Name)
				if err != nil {
					return err
				}
				if len(state) != 0 {
					return fmt.Errorf("stale ACL table state exists for new policy")
				}
				counterMap, err := m.aclRead(ctx, "COUNTERS_DB", "ACL_COUNTER_RULE_MAP")
				if err != nil {
					return err
				}
				for rule := range counterMap {
					if strings.HasPrefix(rule, s.Name+":") {
						return fmt.Errorf("stale ACL runtime exists for new policy")
					}
				}
			}
		}
		return aclCapability(ctx, m.aclRead, latest["ACL_TABLE|"+s.Name] == nil)
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		latest, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return false, nil, err
		}
		ports := aclPorts(latest["ACL_TABLE|"+s.Name]["ports@"])
		return aclRuntime(ctx, s.Name, desired, ports, m.aclRead, m.aclScan)
	}
	return p, nil
}

func aclPorts(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func aclBindingInterfaces(db vlanChangeDB, interfaces []string) ([]string, error) {
	if len(interfaces) == 0 || len(interfaces) > 256 {
		return nil, fmt.Errorf("ACL binding requires 1..256 interfaces")
	}
	ports := append([]string(nil), interfaces...)
	sort.Strings(ports)
	for i, name := range ports {
		_, ethernet := ethernetNumber(name)
		n, err := strconv.ParseUint(strings.TrimPrefix(name, "PortChannel"), 10, 16)
		lag := err == nil && name == "PortChannel"+strconv.FormatUint(n, 10)
		if (!ethernet && !lag) || (i > 0 && ports[i-1] == name) {
			return nil, fmt.Errorf("invalid/duplicate ACL interface")
		}
		table := "PORT"
		if lag {
			table = "PORTCHANNEL"
		}
		if len(db[table+"|"+name]) == 0 {
			return nil, fmt.Errorf("ACL interface does not exist")
		}
		if ethernet {
			for key := range db {
				if strings.HasPrefix(key, "PORTCHANNEL_MEMBER|") && strings.HasSuffix(key, "|"+name) {
					return nil, fmt.Errorf("ACL cannot bind a LAG member")
				}
			}
		}
	}
	return ports, nil
}

// Parse existing native configuration through the same typed contract. A valid
// catchall alone does not establish completeness; the journal check below does.
func aclExistingPolicy(db vlanChangeDB, name string) (vlanChangeDB, error) {
	target := aclPolicyTarget(db, name)
	table := target["ACL_TABLE|"+name]
	if len(table) != 2 || table["stage"] != "INGRESS" || (table["type"] != "L3" && table["type"] != "L3V6") {
		return nil, fmt.Errorf("complete native ingress ACL table required")
	}
	s := aclPolicySpec{Name: name, Family: "IPv4"}
	if table["type"] == "L3V6" {
		s.Family = "IPv6"
	}
	action := func(value string) string {
		if value == "FORWARD" {
			return "Permit"
		}
		if value == "DROP" {
			return "Drop"
		}
		return ""
	}
	s.DefaultAction = action(target["ACL_RULE|"+name+"|"+aclDefaultRule]["PACKET_ACTION"])
	for key, fields := range target {
		if !strings.HasPrefix(key, "ACL_RULE|") || key == "ACL_RULE|"+name+"|"+aclDefaultRule {
			continue
		}
		priority, err := strconv.ParseUint(fields["PRIORITY"], 10, 32)
		if err != nil {
			return nil, err
		}
		r := aclRuleSpec{Name: strings.TrimPrefix(key, "ACL_RULE|"+name+"|"), Priority: uint32(priority), Action: action(fields["PACKET_ACTION"]), Source: fields["SRC_IP"], Destination: fields["DST_IP"]}
		protocol := "IP_PROTOCOL"
		if s.Family == "IPv6" {
			r.Source, r.Destination, protocol = fields["SRC_IPV6"], fields["DST_IPV6"], "NEXT_HEADER"
		}
		for field, ptr := range map[string]**uint32{protocol: &r.Protocol, "L4_SRC_PORT": &r.SourcePort, "L4_DST_PORT": &r.DestinationPort} {
			if value, ok := fields[field]; ok {
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return nil, err
				}
				v := uint32(n)
				*ptr = &v
			}
		}
		s.Rules = append(s.Rules, r)
	}
	desired, err := aclPolicyDesired(s)
	if err != nil || !reflect.DeepEqual(desired, target) {
		return nil, fmt.Errorf("ACL policy is incomplete or contains unsupported fields")
	}
	return desired, nil
}

// Called while the shared engine already holds the journal lock.
func aclPolicyCompleted(m *SonicAgent, name string, desired vlanChangeDB) error {
	if m.networkJournalDir == "" {
		return fmt.Errorf("ACL policy completion journal required")
	}
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return err
	}
	defer root.Close()
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	if err != nil {
		return err
	}
	r := state.Records["ACLPolicy|"+name]
	if r == nil || r.Kind != "ACLPolicy" || r.Pending != nil || !reflect.DeepEqual(r.Fields, desired) {
		return fmt.Errorf("ACL binding requires a complete durably staged policy")
	}
	return nil
}

func planNetworkACLBinding(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s aclBindingSpec
	if err := aclDecode(r, "ACLBinding", &s); err != nil {
		return nil, err
	}
	if !aclName.MatchString(s.Policy) {
		return nil, fmt.Errorf("invalid ACL policy name")
	}
	ports, err := aclBindingInterfaces(db, s.Interfaces)
	if err != nil {
		return nil, err
	}
	desired, err := aclExistingPolicy(db, s.Policy)
	if err != nil {
		return nil, err
	}
	if err := aclPolicyConfigSafe(db, desired, s.Policy); err != nil {
		return nil, err
	}
	key, value := "ACL_TABLE|"+s.Policy, strings.Join(ports, ",")
	if old := db[key]["ports@"]; old != "" && old != value {
		return nil, fmt.Errorf("ACL binding is immutable")
	}
	p := &networkPlan{Identity: "ACLBinding|" + s.Policy, Desired: vlanChangeDB{key: {"ports@": value}}}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		latest, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return err
		}
		if _, err := aclBindingInterfaces(latest, ports); err != nil {
			return err
		}
		if !reflect.DeepEqual(aclPolicyTarget(latest, s.Policy), desired) {
			return fmt.Errorf("ACL policy changed before binding")
		}
		if err := aclPolicyConfigSafe(latest, desired, s.Policy); err != nil {
			return err
		}
		if err := aclPolicyCompleted(m, s.Policy, desired); err != nil {
			return err
		}
		if err := aclCapability(ctx, m.aclRead, false); err != nil {
			return err
		}
		if _, err := aclPortObjects(ctx, ports, m.aclRead); err != nil {
			return err
		}
		old := latest[key]["ports@"]
		if old != "" && old != value {
			return fmt.Errorf("ACL binding changed")
		}
		// Before first binding prove zero existing ASIC attachments. During a
		// no-op/recovery prove the exact requested attachments instead.
		ok, _, err := aclRuntime(ctx, s.Policy, desired, aclPorts(old), m.aclRead, m.aclScan)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("ACL table/rules/counters/bindings are not completely applied")
		}
		return nil
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		if err := aclPolicyCompleted(m, s.Policy, desired); err != nil {
			raw, _ := json.Marshal(map[string]string{"policy": s.Policy, "reason": err.Error()})
			return false, raw, nil
		}
		return aclRuntime(ctx, s.Policy, desired, ports, m.aclRead, m.aclScan)
	}
	return p, nil
}
