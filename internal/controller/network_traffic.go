// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
)

var trafficName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var trafficQoSName = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9_]{0,31}$`)

func isTrafficKind(kind string) bool {
	switch kind {
	case "ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding":
		return true
	default:
		return false
	}
}

// trafficDesired mirrors admission checks for fake/admission-bypassing callers.
// Device-dependent bounds and applied dependency evidence belong to agent preflight.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func trafficDesired(spec any) (string, error) {
	validName := func(name api.TrafficPolicyName) bool { return trafficName.MatchString(string(name)) }
	validQoSName := func(name api.QoSPolicyName) bool { return trafficQoSName.MatchString(string(name)) }
	action := func(value api.ACLAction) bool { return value == "Permit" || value == "Drop" }
	switch s := spec.(type) {
	case *api.SwitchACLPolicySpec:
		if !validName(s.Name) || (s.Family != "IPv4" && s.Family != "IPv6") || !action(s.DefaultAction) || s.Rules == nil || len(s.Rules) > 256 {
			return "", fmt.Errorf("invalid ACL policy name, family, defaultAction or rules")
		}
		names, priorities := map[api.TrafficPolicyName]bool{"DEFAULT": true}, map[uint32]bool{}
		for _, r := range s.Rules {
			if !validName(r.Name) || names[r.Name] || r.Priority < 2 || r.Priority > 999999 || priorities[r.Priority] || !action(r.Action) {
				return "", fmt.Errorf("invalid or duplicate ACL rule name, priority or action")
			}
			names[r.Name], priorities[r.Priority] = true, true
			for _, value := range []api.NetworkPrefix{r.Source, r.Destination} {
				if value == "" {
					continue
				}
				p, err := netip.ParsePrefix(string(value))
				if err != nil || p.Addr().Is4In6() || p.Masked().String() != string(value) || p.Addr().Is4() != (s.Family == "IPv4") {
					return "", fmt.Errorf("ACL prefixes must be canonical and match policy family")
				}
			}
			if r.Protocol != nil && (*r.Protocol < 1 || *r.Protocol > 143) {
				return "", fmt.Errorf("ACL protocol must be 1..143")
			}
			for _, port := range []*uint32{r.SourcePort, r.DestinationPort} {
				if port != nil && (*port > 65535 || r.Protocol == nil || (*r.Protocol != 6 && *r.Protocol != 17)) {
					return "", fmt.Errorf("ACL ports must be 0..65535 with explicit TCP or UDP protocol")
				}
			}
		}
		return string(s.Name), nil
	case *api.SwitchACLBindingSpec:
		if !validName(s.Policy) || len(s.Interfaces) == 0 || len(s.Interfaces) > 256 {
			return "", fmt.Errorf("ACL binding requires a policy and interfaces")
		}
		seen := map[string]bool{}
		for _, name := range s.Interfaces {
			if len(name) > 32 || (!networkEthernet.MatchString(name) && !networkPortChannel.MatchString(name)) || seen[name] {
				return "", fmt.Errorf("invalid or duplicate ACL interface")
			}
			seen[name] = true
		}
		return string(s.Policy), nil
	case *api.SwitchQoSMapSpec:
		if !validQoSName(s.Name) || (s.Type != "DSCPToTC" && s.Type != "Dot1pToTC" && s.Type != "TCToQueue") || len(s.Entries) == 0 || len(s.Entries) > 256 {
			return "", fmt.Errorf("invalid QoS map name, type or entries")
		}
		seen := map[uint32]bool{}
		for _, e := range s.Entries {
			if seen[e.From] || (s.Type == "DSCPToTC" && e.From > 63) || (s.Type == "Dot1pToTC" && e.From > 7) {
				return "", fmt.Errorf("invalid or duplicate QoS map input")
			}
			seen[e.From] = true
		}
		return s.Type + "/" + string(s.Name), nil
	case *api.SwitchSchedulerSpec:
		if !validQoSName(s.Name) || (s.Algorithm != "STRICT" && s.Algorithm != "WRR" && s.Algorithm != "DWRR") {
			return "", fmt.Errorf("invalid scheduler name or algorithm")
		}
		if (s.Algorithm == "STRICT" && s.Weight != nil) || (s.Algorithm != "STRICT" && s.Weight == nil) || (s.Weight != nil && (*s.Weight < 1 || *s.Weight > 100)) {
			return "", fmt.Errorf("STRICT forbids weight; weighted schedulers require weight 1..100")
		}
		if s.MeterType == "" {
			s.MeterType = "Bytes"
		}
		if s.MeterType != "Bytes" && s.MeterType != "Packets" {
			return "", fmt.Errorf("invalid scheduler meterType")
		}
		for _, value := range []*uint64{s.CommittedRate, s.PeakRate, s.CommittedBurst, s.PeakBurst} {
			if value != nil && (*value == 0 || *value > math.MaxInt64) {
				return "", fmt.Errorf("scheduler rates and bursts must be 1..9223372036854775807")
			}
		}
		if s.PeakRate != nil && (s.CommittedRate == nil || *s.PeakRate < *s.CommittedRate) {
			return "", fmt.Errorf("peakRate requires committedRate and must be >= committedRate")
		}
		if (s.CommittedBurst != nil && s.CommittedRate == nil) || (s.PeakBurst != nil && s.PeakRate == nil) || (s.CommittedBurst != nil && s.PeakBurst != nil && *s.PeakBurst < *s.CommittedBurst) {
			return "", fmt.Errorf("bursts require corresponding rates and peakBurst >= committedBurst")
		}
		return string(s.Name), nil
	case *api.SwitchQoSBindingSpec:
		if len(s.InterfaceName) > 32 || !networkEthernet.MatchString(s.InterfaceName) || len(s.Queues) > 256 || (s.DSCPToTC == "" && s.Dot1pToTC == "" && s.TCToQueue == "" && len(s.Queues) == 0) {
			return "", fmt.Errorf("QoS binding requires an Ethernet interface and at least one binding")
		}
		for _, name := range []api.QoSPolicyName{s.DSCPToTC, s.Dot1pToTC, s.TCToQueue} {
			if name != "" && !validQoSName(name) {
				return "", fmt.Errorf("invalid QoS map reference")
			}
		}
		seen := map[uint32]bool{}
		for _, q := range s.Queues {
			if seen[q.Index] || !validQoSName(q.Scheduler) {
				return "", fmt.Errorf("invalid or duplicate queue binding")
			}
			seen[q.Index] = true
		}
		return s.InterfaceName, nil
	default:
		return "", fmt.Errorf("unsupported traffic spec")
	}
}
