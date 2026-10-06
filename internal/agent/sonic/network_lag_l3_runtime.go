// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
)

type lagL3AppReader func(context.Context, string) (map[string]string, error)
type lagL3LinkReader func(string) (netlink.Link, error)
type lagL3CommandReader func(context.Context, ...string) ([]byte, error)

// Absence is a successful observation during creation/convergence, not an
// inability to read runtime state. Match only netlink's typed not-found error;
// permissions, transport failures and untyped error strings must propagate.
func lagL3LinkObservationError(ctx context.Context, name string, err error) (bool, json.RawMessage, error) {
	if ctx.Err() != nil {
		return false, nil, ctx.Err()
	}
	var missing netlink.LinkNotFoundError
	var missingPointer *netlink.LinkNotFoundError
	if errors.As(err, &missing) || errors.As(err, &missingPointer) {
		raw, _ := json.Marshal(map[string]any{"name": name, "kernelLinkExists": false})
		return false, raw, nil
	}
	return false, nil, err
}

func (m *SonicAgent) lagL3ReadApp(ctx context.Context, key string) (map[string]string, error) {
	return m.breakoutDB("APPL_DB").HGetAll(ctx, key).Result()
}

// Do not embed bytes.Buffer: its promoted ReadFrom would bypass Write's limit
// when os/exec copies a pipe with io.Copy.
type lagL3BoundedOutput struct{ buffer bytes.Buffer }

func (b *lagL3BoundedOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 1<<20 {
		return 0, fmt.Errorf("runtime output exceeds 1 MiB")
	}
	return b.buffer.Write(p)
}

// Only callers with canonical, planner-validated arguments reach this helper.
// No shell, no config-mode vtysh, bounded time/output, and no raw stderr in status.
func lagL3Run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.WaitDelay = time.Second
	var out lagL3BoundedOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read-only runtime command failed: %w", err)
	}
	return out.buffer.Bytes(), nil
}

func lagL3VRFRuntime(ctx context.Context, name string, read lagL3AppReader, link lagL3LinkReader) (bool, json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	fields, err := read(ctx, "VRF_TABLE:"+name)
	if err != nil {
		return false, nil, err
	}
	l, err := link(name)
	if err != nil {
		return lagL3LinkObservationError(ctx, name, err)
	}
	vrf, ok := l.(*netlink.Vrf)
	valid := ok && vrf != nil && vrf.Table >= 1001 && vrf.Table < 5097 && len(fields) > 0
	raw, _ := json.Marshal(map[string]any{"name": name, "appl": fields, "kernelVRF": valid})
	return valid, raw, ctx.Err()
}

func lagL3InterfaceRuntime(ctx context.Context, name, vrf string, addresses []string, read lagL3AppReader, link lagL3LinkReader) (bool, json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	fields, err := read(ctx, "INTF_TABLE:"+name)
	if err != nil {
		return false, nil, err
	}
	bound := fields["vrf_name"]
	if bound == "" {
		bound = "default"
	}
	valid := len(fields) > 0 && bound == vrf
	l, err := link(name)
	if err != nil {
		return lagL3LinkObservationError(ctx, name, err)
	}
	if l == nil || l.Attrs() == nil {
		return false, nil, fmt.Errorf("missing kernel interface")
	}
	if vrf != "default" {
		master, err := link(vrf)
		if err != nil {
			return lagL3LinkObservationError(ctx, vrf, err)
		}
		v, ok := master.(*netlink.Vrf)
		valid = valid && ok && v != nil && v.Attrs() != nil && v.Attrs().Index > 0 && l.Attrs().MasterIndex == v.Attrs().Index
	} else {
		valid = valid && l.Attrs().MasterIndex == 0
	}
	observed := map[string]map[string]string{name: fields}
	for _, address := range addresses {
		fields, err := read(ctx, "INTF_TABLE:"+name+":"+address)
		if err != nil {
			return false, nil, err
		}
		p, err := netip.ParsePrefix(address)
		if err != nil {
			return false, nil, err
		}
		family := "IPv6"
		if p.Addr().Is4() {
			family = "IPv4"
		}
		valid = valid && fields["family"] == family && fields["scope"] == "global"
		observed[address] = fields
	}
	raw, _ := json.Marshal(map[string]any{"name": name, "vrf": vrf, "appl": observed})
	return valid, raw, ctx.Err()
}

func lagL3PortChannelRuntime(ctx context.Context, name string, members []string, want map[string]string, read lagL3AppReader, link lagL3LinkReader, run lagL3CommandReader) (bool, json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	fields, err := read(ctx, "LAG_TABLE:"+name)
	if err != nil {
		return false, nil, err
	}
	l, err := link(name)
	if err != nil {
		return lagL3LinkObservationError(ctx, name, err)
	}
	if l == nil || l.Attrs() == nil {
		return false, nil, fmt.Errorf("missing kernel LAG")
	}
	mtu, _ := strconv.Atoi(want["mtu"])
	valid := l.Type() == "team" && l.Attrs().Index > 0 && fields["mtu"] == want["mtu"] && l.Attrs().MTU == mtu && ((l.Attrs().Flags&net.FlagUp != 0) == (want["admin_status"] == "up"))
	for _, member := range members {
		child, err := link(member)
		if err != nil {
			return lagL3LinkObservationError(ctx, member, err)
		}
		valid = valid && child != nil && child.Attrs() != nil && child.Attrs().MasterIndex == l.Attrs().Index
	}
	raw, err := run(ctx, "docker", "exec", "teamd", "teamdctl", name, "config", "dump")
	if err != nil {
		return false, nil, err
	}
	var config struct {
		Device string `json:"device"`
		Runner struct {
			Name     string `json:"name"`
			Active   bool   `json:"active"`
			MinPorts int    `json:"min_ports"`
			FastRate bool   `json:"fast_rate"`
		} `json:"runner"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return false, nil, fmt.Errorf("invalid teamd runtime JSON")
	}
	minLinks, _ := strconv.Atoi(want["min_links"])
	valid = valid && config.Device == name && config.Runner.Name == "lacp" && config.Runner.Active && config.Runner.MinPorts == minLinks && config.Runner.FastRate == (want["fast_rate"] == "true")
	observed, _ := json.Marshal(map[string]any{"name": name, "appl": fields, "runner": config.Runner})
	return valid, observed, ctx.Err()
}

func lagL3RouteRuntime(ctx context.Context, vrf, prefix string, hops []lagL3NextHop, expectedTag uint32, run lagL3CommandReader) (bool, json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false, nil, err
	}
	family := "ipv6"
	if p.Addr().Is4() {
		family = "ip"
	}
	command := "show " + family + " route"
	if vrf != "default" {
		command += " vrf " + vrf
	}
	command += " " + prefix + " json"
	raw, err := run(ctx, "docker", "exec", "bgp", "vtysh", "-c", command)
	if err != nil {
		return false, nil, err
	}
	var routes map[string][]struct {
		Protocol string `json:"protocol"`
		Distance uint32 `json:"distance"`
		Tag      uint32 `json:"tag"`
		NextHops []struct {
			IP            string `json:"ip"`
			InterfaceName string `json:"interfaceName"`
			Active        bool   `json:"active"`
		} `json:"nexthops"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return false, nil, fmt.Errorf("invalid FRR route JSON")
	}
	valid := true
	for _, want := range hops {
		found := false
		for _, route := range routes[prefix] {
			if route.Protocol != "static" || route.Distance != *want.Distance || route.Tag != expectedTag {
				continue
			}
			for _, hop := range route.NextHops {
				ip, err := netip.ParseAddr(hop.IP)
				if err == nil && ip.String() == want.Address && hop.Active && (want.InterfaceName == "" || hop.InterfaceName == want.InterfaceName) {
					found = true
				}
			}
		}
		valid = valid && found
	}
	observed, _ := json.Marshal(map[string]any{"vrf": vrf, "prefix": prefix, "routes": routes[prefix]})
	return valid, observed, ctx.Err()
}
