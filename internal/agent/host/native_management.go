// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
)

func managementRuleMatches(a Address, data []byte) bool {
	var rules []struct {
		Priority int    `json:"priority"`
		Source   string `json:"src"`
		Table    any    `json:"table"`
	}
	if json.Unmarshal(data, &rules) != nil {
		return false
	}
	p, _ := netip.ParsePrefix(a.Prefix)
	for _, r := range rules {
		if r.Priority == 32765 && strings.TrimSuffix(strings.TrimSuffix(r.Source, "/32"), "/128") == p.Addr().String() && (r.Table == "default" || r.Table == float64(253)) {
			return true
		}
	}
	return false
}
func (n *Native) Snapshot(ctx context.Context) (Snapshot, error) {
	db, e := n.Load(ctx)
	if e != nil {
		return Snapshot{}, ErrNative
	}
	mac, e := n.bootMAC()
	if e != nil {
		return Snapshot{}, ErrNative
	}
	m, e := managementFromDB(db, mac)
	if e != nil {
		return Snapshot{}, e
	}
	b, e := n.run(ctx, "ip", "-j", "address", "show", "dev", "eth0")
	if e != nil {
		return Snapshot{}, e
	}
	var links []struct {
		MAC string `json:"address"`
	}
	if json.Unmarshal(b, &links) != nil || len(links) != 1 {
		return Snapshot{}, ErrNative
	}
	active := m
	active.MAC = links[0].MAC
	if active.MAC == "" || ValidateManagement(active) != nil {
		return Snapshot{}, ErrNative
	}
	return Snapshot{Management: m, ActiveMAC: links[0].MAC}, nil
}
func (n *Native) render(ctx context.Context, after Database, template string, container bool) ([]byte, error) {
	b, e := n.run(ctx, "sonic-cfggen", "-d", "--print-data")
	if e != nil {
		return nil, e
	}
	var all map[string]json.RawMessage
	if json.Unmarshal(b, &all) != nil {
		return nil, ErrNative
	}
	if template == interfacesTemplate {
		all["ZTP_DHCP_DISABLED"] = json.RawMessage(`"true"`)
	}
	for _, table := range []string{"MGMT_INTERFACE", "NTP", "NTP_SERVER", "SNMP", "SNMP_COMMUNITY"} {
		if rows, ok := after[table]; ok {
			all[table], e = json.Marshal(rows)
			if e != nil {
				return nil, ErrNative
			}
		}
	}
	b, e = json.Marshal(all)
	if e != nil {
		return nil, ErrNative
	}
	args := []string{"sonic-cfggen", "-j", "/dev/stdin", "-t", template}
	if container {
		state, e := n.snmpContainer(ctx)
		if e != nil {
			return nil, e
		}
		if !state.State.Running {
			return n.renderStoppedSNMP(ctx, template, b)
		}
		args = append([]string{"docker", "exec", "-i", "snmp"}, args...)
	}
	f := n.Run
	if f == nil {
		f = boundedRun
	}
	out, e := f(ctx, args, b)
	if e != nil {
		return nil, ErrNative
	}
	return out, nil
}
func (n *Native) ApplyManagement(ctx context.Context, before Snapshot, m Management) error {
	if ValidateManagement(m) != nil {
		return ErrInvalid
	}
	return n.mutate(ctx, func() error {
		current, e := n.Snapshot(ctx)
		if e != nil || !managementEqual(current.Management, before.Management) || current.ActiveMAC != before.ActiveMAC {
			return ErrConflict
		}
		return n.applyManagement(ctx, current, m, m.MAC, m.MAC != "")
	})
}
func (n *Native) RestoreManagement(ctx context.Context, scope RecoveryScope) error {
	before := scope.Before
	if ValidateManagement(before.Management) != nil || ValidateManagement(scope.Candidate) != nil {
		return ErrInvalid
	}
	for _, mac := range []string{before.ActiveMAC, scope.ObservedActiveMAC} {
		if mac == "" {
			continue
		}
		m := before.Management
		m.MAC = mac
		if ValidateManagement(m) != nil {
			return ErrInvalid
		}
	}
	return n.mutate(ctx, func() error {
		current, e := n.Snapshot(ctx)
		if e != nil {
			return e
		}
		cleanup := append([]Address{}, before.Management.Addresses...)
		for _, a := range scope.Candidate.Addresses {
			found := false
			for _, b := range cleanup {
				found = found || a == b
			}
			if !found {
				cleanup = append(cleanup, a)
			}
		}
		for _, a := range current.Management.Addresses {
			allowed := false
			for _, b := range cleanup {
				allowed = allowed || a == b
			}
			if !allowed {
				return ErrConflict
			}
		}
		if current.ActiveMAC != before.ActiveMAC && current.ActiveMAC != scope.Candidate.MAC && (scope.ObservedActiveMAC == "" || current.ActiveMAC != scope.ObservedActiveMAC) {
			return ErrConflict
		}
		current.Management.Addresses = cleanup
		if e = n.applyManagement(ctx, current, before.Management, before.ActiveMAC, true); e != nil {
			return e
		}
		restored, e := n.Snapshot(ctx)
		if e != nil || restored.ActiveMAC != before.ActiveMAC || !managementEqual(restored.Management, before.Management) {
			return ErrNative
		}
		return n.verifyRestoredScope(ctx, scope)
	})
}

func (n *Native) verifyRestoredScope(ctx context.Context, scope RecoveryScope) error {
	for _, a := range scope.Candidate.Addresses {
		p, _ := netip.ParsePrefix(a.Prefix)
		keepPrefix, keepSource, keepSubnet := false, false, false
		for _, b := range scope.Before.Management.Addresses {
			bp, _ := netip.ParsePrefix(b.Prefix)
			keepPrefix = keepPrefix || a.Prefix == b.Prefix
			keepSource = keepSource || p.Addr() == bp.Addr()
			keepSubnet = keepSubnet || p.Masked() == bp.Masked()
		}
		if !keepPrefix {
			present, e := n.addressPresent(ctx, a.Prefix)
			if e != nil || present {
				return ErrNative
			}
		}
		if !keepSource {
			b, e := n.run(ctx, "ip", family(a.Prefix), "-j", "rule", "show")
			if e != nil || managementRuleMatches(a, b) {
				return ErrNative
			}
		}
		if !keepSubnet {
			b, e := n.run(ctx, "ip", family(a.Prefix), "-j", "route", "show", "table", "default", "exact", p.Masked().String(), "dev", "eth0")
			var routes []json.RawMessage
			if e != nil || json.Unmarshal(b, &routes) != nil || len(routes) != 0 {
				return ErrNative
			}
		}
	}
	return nil
}
func (n *Native) applyManagement(ctx context.Context, before Snapshot, m Management, activeMAC string, manageMAC ...bool) error {
	db, e := n.Load(ctx)
	if e != nil {
		return ErrNative
	}
	after, e := managementDatabase(db, m)
	if e != nil {
		return e
	}
	// Render the complete candidate through the qualified native generator before
	// changing Redis or kernel state. The full config exists in private pipes only.
	generated, e := n.render(ctx, after, interfacesTemplate, false)
	if e != nil {
		return e
	}
	if e = n.CAS(ctx, db, after); e != nil {
		return e
	}
	if e = n.write("/etc/network/interfaces", generated, 0644); e != nil {
		return e
	}
	if len(manageMAC) == 0 || manageMAC[0] {
		boot, e := json.Marshal(struct {
			MAC string `json:"mac"`
		}{m.MAC})
		if e != nil {
			return ErrNative
		}
		if e = n.write(bootFile, boot, 0600); e != nil {
			return e
		}
		if m.MAC != "" {
			if e = n.write(macDropIn, []byte(macUnit), 0644); e != nil {
				return e
			}
			if _, e = n.run(ctx, "systemctl", "daemon-reload"); e != nil {
				return e
			}
		}
	}
	if activeMAC != "" && before.ActiveMAC != activeMAC {
		// Only a changed MAC needs a link cycle; address/gateway edits never do.
		if _, e = n.run(ctx, "ip", "link", "set", "dev", "eth0", "down"); e != nil {
			return e
		}
		if _, e = n.run(ctx, "ip", "link", "set", "dev", "eth0", "address", activeMAC); e != nil {
			return e
		}
		if _, e = n.run(ctx, "ip", "link", "set", "dev", "eth0", "up"); e != nil {
			return e
		}
	}
	if _, e = n.run(ctx, "ip", "link", "set", "dev", "eth0", "up"); e != nil {
		return e
	}
	for _, a := range m.Addresses {
		if _, e = n.run(ctx, "ip", family(a.Prefix), "address", "replace", a.Prefix, "dev", "eth0"); e != nil {
			return e
		}
		p, _ := netip.ParsePrefix(a.Prefix)
		if _, e = n.run(ctx, "ip", family(a.Prefix), "route", "replace", p.Masked().String(), "dev", "eth0", "table", "default"); e != nil {
			return e
		}
		if a.Gateway != "" {
			if _, e = n.run(ctx, "ip", family(a.Prefix), "route", "replace", "default", "via", a.Gateway, "dev", "eth0", "table", "default", "metric", "201"); e != nil {
				return e
			}
		}
		rules, e := n.run(ctx, "ip", family(a.Prefix), "-j", "rule", "show")
		if e != nil {
			return e
		}
		if !managementRuleMatches(a, rules) {
			if _, e = n.run(ctx, "ip", family(a.Prefix), "rule", "add", "priority", "32765", "from", p.Addr().String(), "table", "default"); e != nil {
				return e
			}
		}
	}
	for _, a := range before.Management.Addresses {
		p, _ := netip.ParsePrefix(a.Prefix)
		keepPrefix, keepSubnet, keepGateway, keepSource := false, false, false, false
		for _, d := range m.Addresses {
			dp, _ := netip.ParsePrefix(d.Prefix)
			keepPrefix = keepPrefix || d.Prefix == a.Prefix
			keepSubnet = keepSubnet || dp.Masked() == p.Masked()
			keepSource = keepSource || dp.Addr() == p.Addr()
			keepGateway = keepGateway || (d.Gateway != "" && family(d.Prefix) == family(a.Prefix))
		}
		if !keepPrefix {
			present, e := n.addressPresent(ctx, a.Prefix)
			if e != nil {
				return e
			}
			if present {
				if _, e = n.run(ctx, "ip", family(a.Prefix), "address", "del", a.Prefix, "dev", "eth0"); e != nil {
					return e
				}
			}
			rules, e := n.run(ctx, "ip", family(a.Prefix), "-j", "rule", "show")
			if e != nil {
				return e
			}
			if !keepSource && managementRuleMatches(a, rules) {
				if _, e = n.run(ctx, "ip", family(a.Prefix), "rule", "del", "priority", "32765", "from", p.Addr().String(), "table", "default"); e != nil {
					return e
				}
			}
		}
		if !keepSubnet {
			if e = n.deleteManagementRoute(ctx, a, p.Masked().String(), ""); e != nil {
				return e
			}
		}
		if a.Gateway != "" && !keepGateway {
			if e = n.deleteManagementRoute(ctx, a, "default", a.Gateway); e != nil {
				return e
			}
		}
	}
	if n.Save(ctx) != nil {
		return ErrNative
	}
	return nil
}

func (n *Native) addressPresent(ctx context.Context, prefix string) (bool, error) {
	b, e := n.run(ctx, "ip", "-j", "address", "show", "dev", "eth0")
	if e != nil {
		return false, e
	}
	var links []struct {
		Info []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(b, &links) != nil || len(links) != 1 {
		return false, ErrNative
	}
	for _, a := range links[0].Info {
		if a.Local+"/"+strconv.Itoa(a.PrefixLen) == prefix {
			return true, nil
		}
	}
	return false, nil
}
func (n *Native) deleteManagementRoute(ctx context.Context, a Address, prefix, gateway string) error {
	b, e := n.run(ctx, "ip", family(a.Prefix), "-j", "route", "show", "table", "default", "exact", prefix, "dev", "eth0")
	if e != nil {
		return e
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	if json.Unmarshal(b, &routes) != nil {
		return ErrNative
	}
	for _, r := range routes {
		if gateway != "" && (r.Gateway != gateway || r.Metric != 201) {
			continue
		}
		args := []string{"ip", family(a.Prefix), "route", "del", prefix, "dev", "eth0", "table", "default"}
		if gateway != "" {
			args = append(args, "via", gateway, "metric", "201")
		}
		if _, e = n.run(ctx, args...); e != nil {
			return e
		}
	}
	return nil
}

// ApplyBootMAC is used only by the installed local boot helper. It consumes the
// typed root-owned persisted MAC input, never a command supplied by an RPC.
func (n *Native) ApplyBootMAC(ctx context.Context) error {
	mac, e := n.bootMAC()
	if e != nil {
		return e
	}
	if mac == "" {
		return nil
	}
	m := Management{Interface: "eth0", MAC: mac, Addresses: []Address{{Prefix: "192.0.2.1/24"}}}
	if ValidateManagement(m) != nil {
		return ErrInvalid
	}
	b, e := n.run(ctx, "ip", "-j", "address", "show", "dev", "eth0")
	if e != nil {
		return e
	}
	var links []struct {
		MAC string `json:"address"`
	}
	if json.Unmarshal(b, &links) != nil || len(links) != 1 {
		return ErrNative
	}
	if links[0].MAC == mac {
		return nil
	}
	db, e := n.saved()
	if e != nil {
		return e
	}
	management, e := managementFromDB(db, mac)
	if e != nil {
		return e
	}
	for _, args := range [][]string{{"ip", "link", "set", "dev", "eth0", "down"}, {"ip", "link", "set", "dev", "eth0", "address", mac}, {"ip", "link", "set", "dev", "eth0", "up"}} {
		if _, e = n.run(ctx, args...); e != nil {
			return e
		}
	}
	// A raw link cycle removes SONiC's management-table routes without running
	// ifupdown hooks. Rebuild only the declared management policy table.
	for _, a := range management.Addresses {
		p, _ := netip.ParsePrefix(a.Prefix)
		if _, e = n.run(ctx, "ip", family(a.Prefix), "route", "replace", p.Masked().String(), "dev", "eth0", "table", "default"); e != nil {
			return e
		}
		if a.Gateway != "" {
			if _, e = n.run(ctx, "ip", family(a.Prefix), "route", "replace", "default", "via", a.Gateway, "dev", "eth0", "table", "default", "metric", "201"); e != nil {
				return e
			}
		}
	}
	return nil
}
