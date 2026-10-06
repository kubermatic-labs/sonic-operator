// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type routingReadCommand uint8

const (
	routingBGPConfig routingReadCommand = iota
	routingBGPDaemons
	routingBGPSummary
	routingRelayProcesses
	routingRelayContainer
	routingRelayGenerated
	routingRelayRendered
	routingRelayProcessIdentity
)

type routingRead func(context.Context, routingReadCommand) ([]byte, error)

// Private execution seam used by real-planner/engine tests. Production callers
// cannot select commands through RPC; argv is built exclusively below.
type routingCommandRunnerKey struct{}
type routingCommandRunner func(*exec.Cmd) ([]byte, error)

func routingPeerPreflight(ctx context.Context, run routingRead, asn uint32, routerID string, prefixes []string, staged routingPeerSpec) error {
	staged.AdminState = "Down"
	verified, _, err := observeRoutingBGP(ctx, run, staged.VRF, asn, routerID, prefixes, &staged)
	if err != nil {
		return err
	}
	if !verified {
		return fmt.Errorf("peer activation preflight failed: FRR shutdown, AFs, maximum-prefix and exact export filters must match staged policy")
	}
	return nil
}

// A Redis shutdown is only intent. Check every actual neighbor in the target
// instance, including neighbors absent from CONFIG_DB, before global edits.
func routingShutdownPreflight(ctx context.Context, run routingRead, vrf string, asn uint32, peer string) error {
	daemons, err := run(ctx, routingBGPDaemons)
	if err != nil {
		return err
	}
	running := map[string]bool{}
	for _, line := range strings.Split(string(daemons), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[1] == "RUNNING" {
			running[fields[0]] = true
		}
	}
	if !running["frrcfgd"] || !running["bgpd"] {
		return fmt.Errorf("BGP preflight requires running frrcfgd and bgpd")
	}
	config, err := run(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	inside, safeDefault, noDefaultAF := false, false, false
	neighbors, shutdown, enabled := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(string(config), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) >= 3 && fields[0] == "router" && fields[1] == "bgp" {
			instance := "default"
			if len(fields) == 5 && fields[3] == "vrf" {
				instance = fields[4]
			}
			inside = instance == vrf
			if inside && fields[2] != strconv.FormatUint(uint64(asn), 10) {
				return fmt.Errorf("BGP preflight found a conflicting runtime ASN")
			}
			continue
		}
		if !inside {
			continue
		}
		if strings.TrimSpace(line) == "bgp default shutdown" {
			safeDefault = true
		}
		if strings.TrimSpace(line) == "no bgp default ipv4-unicast" {
			noDefaultAF = true
		}
		if line[0] != ' ' && line[0] != '\t' {
			inside = false
			continue
		}
		if strings.Contains(strings.TrimSpace(line), "bgp listen ") || strings.Contains(strings.TrimSpace(line), " peer-group") {
			return fmt.Errorf("dynamic/inherited runtime peer policy blocks BGP changes")
		}
		if len(fields) >= 3 && fields[0] == "neighbor" {
			if peer != "" && fields[1] != peer {
				continue
			}
			neighbors[fields[1]] = true
			if fields[2] == "shutdown" {
				shutdown[fields[1]] = true
			}
		}
		if len(fields) >= 4 && fields[0] == "no" && fields[1] == "neighbor" && fields[3] == "shutdown" {
			enabled[fields[2]] = true
		}
	}
	for address := range neighbors {
		if !shutdown[address] || enabled[address] {
			return fmt.Errorf("BGP preflight requires actual FRR shutdown before policy changes")
		}
	}
	if peer != "" && (!safeDefault || !noDefaultAF) {
		return fmt.Errorf("peer policy preflight requires FRR default shutdown and disabled default IPv4 AF before creating a neighbor")
	}
	return nil
}

// There is no caller-supplied command, argument, container name or shell script.
// Read all VRFs and select the validated target locally.
func runRoutingRead(ctx context.Context, command routingReadCommand) ([]byte, error) {
	var args []string
	switch command {
	case routingBGPConfig:
		args = []string{"exec", "bgp", "vtysh", "-c", "show running-config"}
	case routingBGPDaemons:
		args = []string{"exec", "bgp", "supervisorctl", "status"}
	case routingBGPSummary:
		args = []string{"exec", "bgp", "vtysh", "-c", "show bgp vrf all summary json"}
	case routingRelayProcesses:
		args = []string{"exec", "dhcp_relay", "ps", "-eo", "args="}
	case routingRelayContainer:
		args = []string{"inspect", "--format", "[{\"Id\":{{json .Id}},\"State\":{\"Running\":{{json .State.Running}},\"StartedAt\":{{json .State.StartedAt}}}}]", "dhcp_relay"}
	case routingRelayGenerated:
		args = []string{"exec", "dhcp_relay", "cat", "/etc/supervisor/conf.d/docker-dhcp-relay.supervisord.conf"}
	case routingRelayRendered:
		args = []string{"exec", "dhcp_relay", "sonic-cfggen", "-d", "-t", "/usr/share/sonic/templates/docker-dhcp-relay.supervisord.conf.j2"}
	case routingRelayProcessIdentity:
		args = []string{"exec", "dhcp_relay", "python3", "-c", routingRelayProcessScript}
	default:
		return nil, fmt.Errorf("unsupported routing read command")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.WaitDelay = time.Second
	if run, ok := ctx.Value(routingCommandRunnerKey{}).(routingCommandRunner); ok {
		return run(cmd)
	}
	var stdout routingBoundedOutput
	cmd.Stdout = &stdout
	// Stderr and FRR config can contain passwords. Never return either raw.
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("routing read %d failed: %w", command, err)
	}
	return stdout.buffer.Bytes(), nil
}

// Fixed read-only /proc query. Numeric PIDs and argv come from the kernel, not
// request input; only relay binaries are returned. No shell is evaluated.
const routingRelayProcessScript = `import os,json
result=[]
for pid in sorted((p for p in os.listdir('/proc') if p.isdigit()), key=int):
    try:
        argv=open('/proc/'+pid+'/cmdline','rb').read().decode().split(chr(0))[:-1]
        if argv and argv[0] in ['/usr/sbin/dhcrelay','/usr/sbin/dhcp4relay','/usr/sbin/dhcp6relay']:
            start=open('/proc/'+pid+'/stat').read().rsplit(')',1)[1].split()[19]
            result.append({'pid':pid,'argv':argv,'start':start})
    except FileNotFoundError:
        pass
print(json.dumps(result,sort_keys=True))`

type routingBoundedOutput struct{ buffer bytes.Buffer }

func (w *routingBoundedOutput) Write(p []byte) (int, error) {
	if w.buffer.Len()+len(p) > 4<<20 {
		return 0, fmt.Errorf("routing observation exceeds 4 MiB")
	}
	return w.buffer.Write(p)
}

func observeRoutingBGP(ctx context.Context, run routingRead, vrf string, asn uint32, routerID string, prefixes []string, peer *routingPeerSpec) (bool, json.RawMessage, error) {
	daemons, err := run(ctx, routingBGPDaemons)
	if err != nil {
		return false, nil, err
	}
	config, err := run(ctx, routingBGPConfig)
	if err != nil {
		return false, nil, err
	}
	summary, err := run(ctx, routingBGPSummary)
	if err != nil {
		return false, nil, err
	}
	var operational map[string]json.RawMessage
	if json.Unmarshal(summary, &operational) != nil || operational == nil {
		return false, nil, fmt.Errorf("invalid FRR summary JSON")
	}
	running := map[string]bool{}
	for _, line := range strings.Split(string(daemons), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "RUNNING" {
			running[parts[0]] = true
		}
	}
	root := "router bgp " + strconv.FormatUint(uint64(asn), 10)
	if vrf != "default" {
		root += " vrf " + vrf
	}
	global := map[string]bool{}
	afLines := map[string]map[string]bool{}
	all := map[string]bool{}
	inside, found, af := false, false, ""
	for _, line := range strings.Split(string(config), "\n") {
		trimmed := strings.TrimSpace(line)
		all[trimmed] = true
		if strings.HasPrefix(trimmed, "router bgp ") {
			inside = trimmed == root || (vrf == "default" && trimmed == root+" vrf default")
			found = found || inside
			af = ""
			continue
		}
		if !inside {
			continue
		}
		if trimmed == "!" && line != trimmed {
			continue // FRR separates address families with indented comments.
		}
		if trimmed == "!" || trimmed == "exit" || trimmed == "end" {
			inside = false
			af = ""
			continue
		}
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			inside = false
			af = ""
			continue
		}
		if strings.HasPrefix(trimmed, "address-family ") {
			af = strings.TrimPrefix(trimmed, "address-family ")
			if afLines[af] == nil {
				afLines[af] = map[string]bool{}
			}
			continue
		}
		if trimmed == "exit-address-family" {
			af = ""
			continue
		}
		if af == "" {
			global[trimmed] = true
		} else {
			afLines[af][trimmed] = true
		}
	}
	matched := found && global["bgp router-id "+routerID] && global["no bgp default ipv4-unicast"] && global["bgp default shutdown"]
	for _, lines := range []map[string]bool{global, afLines["ipv4 unicast"], afLines["ipv6 unicast"]} {
		for line := range lines {
			if strings.HasPrefix(line, "redistribute ") || strings.HasPrefix(line, "aggregate-address ") || strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "network ") {
				// Networks are checked exactly per family below; global network
				// statements and all redistribution/import are never accepted.
				if !strings.HasPrefix(line, "network ") || global[line] {
					matched = false
				}
			}
		}
	}
	for _, family := range []string{"ipv4_unicast", "ipv6_unicast"} {
		name := routingExportName(vrf, family)
		kind, anyPrefix, bits := "ip", "0.0.0.0/0", "32"
		if family == "ipv6_unicast" {
			kind, anyPrefix, bits = "ipv6", "::/0", "128"
		}
		listPrefix := kind + " prefix-list " + name + " "
		expected := map[string]bool{listPrefix + "seq 4294967295 deny " + anyPrefix + " le " + bits: true}
		networks := map[string]bool{}
		seq := 1
		for _, p := range prefixes {
			if strings.Contains(p, ":") != (family == "ipv6_unicast") {
				continue
			}
			expected[fmt.Sprintf("%sseq %d permit %s", listPrefix, seq, p)] = true
			networks["network "+p] = true
			seq++
		}
		for line := range expected {
			if !all[line] {
				matched = false
			}
		}
		for line := range all {
			if strings.HasPrefix(line, listPrefix) && !expected[line] {
				matched = false
			}
		}
		lines := afLines[strings.ReplaceAll(family, "_", " ")]
		for line := range networks {
			if !lines[line] {
				matched = false
			}
		}
		for line := range lines {
			if strings.HasPrefix(line, "network ") && !networks[line] {
				matched = false
			}
		}
		if peer != nil {
			enabled := false
			for _, f := range peer.AddressFamilies {
				if f == map[string]string{"ipv4_unicast": "ipv4Unicast", "ipv6_unicast": "ipv6Unicast"}[family] {
					enabled = true
				}
			}
			nbr := "neighbor " + peer.Address + " "
			if enabled {
				limit := strconv.FormatUint(uint64(*peer.MaxPrefixes), 10)
				if !lines[nbr+"activate"] || !lines[nbr+"prefix-list "+name+" out"] || (!lines[nbr+"maximum-prefix "+limit+" 100"] && !lines[nbr+"maximum-prefix "+limit]) {
					matched = false
				}
				for line := range lines {
					if strings.HasPrefix(line, nbr+"default-originate") || (strings.HasPrefix(line, nbr+"maximum-prefix ") && strings.Contains(line, "warning-only")) {
						matched = false
					}
				}
			} else if lines[nbr+"activate"] {
				matched = false
			}
		}
	}
	peerStates := map[string]string{}
	if peer != nil {
		nbr := "neighbor " + peer.Address + " "
		for line := range global {
			if strings.HasPrefix(line, nbr+"peer-group") || (peer.LocalAddress == "" && strings.HasPrefix(line, nbr+"update-source ")) {
				matched = false
			}
		}
		for family, lines := range afLines {
			if family != "ipv4 unicast" && family != "ipv6 unicast" && lines[nbr+"activate"] {
				matched = false
			}
		}
		if !global[nbr+"remote-as "+strconv.FormatUint(uint64(peer.RemoteASN), 10)] {
			matched = false
		}
		if peer.LocalAddress != "" && !global[nbr+"update-source "+peer.LocalAddress] {
			matched = false
		}
		if peer.AdminState == "Down" && !global[nbr+"shutdown"] {
			matched = false
		}
		if peer.AdminState == "Down" && global["no "+nbr+"shutdown"] {
			matched = false
		}
		// FRR 10.4.1 writes a shutdown line only when the actual peer flag is
		// set; an enabled peer does not render "no neighbor ... shutdown".
		if peer.AdminState == "Up" {
			for line := range global {
				if strings.HasPrefix(line, nbr+"shutdown") {
					matched = false
				}
			}
		}
		// Operational session state is evidence, not a substitute for configured
		// shutdown, AF selection, limits and policy in FRR running-config.
		var families map[string]struct {
			Peers map[string]struct {
				State string `json:"state"`
			} `json:"peers"`
		}
		if raw, ok := operational[vrf]; ok && json.Unmarshal(raw, &families) == nil {
			for family, data := range families {
				if state, ok := data.Peers[peer.Address]; ok {
					peerStates[family] = state.State
				}
			}
		}
	}
	verified := matched && running["frrcfgd"] && running["bgpd"]
	observed, _ := json.Marshal(map[string]any{"vrf": vrf, "consumer": "frrcfgd", "consumerRunning": running["frrcfgd"], "bgpdRunning": running["bgpd"], "runningConfigMatches": matched, "peerStates": peerStates, "forwardingTested": false})
	return verified, observed, nil
}

func observeRoutingRelay(ctx context.Context, run routingRead, vlan string, native bool, v4, v6 []string) (bool, json.RawMessage, error) {
	processes, err := run(ctx, routingRelayProcesses)
	if err != nil {
		return false, nil, err
	}
	v4Running, v6Running, v4Matches := false, false, false
	for _, line := range strings.Split(string(processes), "\n") {
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		if args[0] == "/usr/sbin/dhcp4relay" && native {
			v4Running = true
		}
		if args[0] == "/usr/sbin/dhcp6relay" {
			v6Running = true
		}
		if args[0] != "/usr/sbin/dhcrelay" || native {
			continue
		}
		downstream := false
		var destinations []string
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "-id", "-iu", "-i", "-pg", "-U", "-m", "--name-alias-map-file":
				if i+1 < len(args) {
					if args[i] == "-id" && args[i+1] == vlan {
						downstream = true
					}
					i++
				}
				continue
			case "-a":
				i += 2 // SONiC's circuit-ID and remote-ID format operands.
				continue
			}
			v4Only := true
			if address, err := routingAddress(args[i], &v4Only); err == nil {
				destinations = append(destinations, address.String())
			}
		}
		if downstream {
			v4Running = true
			sort.Strings(destinations)
			v4Matches = routingServerSetEqual(strings.Join(destinations, ","), v4)
		}
	}
	// The native daemons expose no inspected per-VLAN applied-config readback.
	// Process presence alone cannot prove that a new destination was consumed.
	v4Verified := len(v4) == 0 || (!native && v4Matches)
	v6Verified := len(v6) == 0
	observed, _ := json.Marshal(map[string]any{"vlan": vlan, "ipv4DaemonRunning": v4Running, "ipv6DaemonRunning": v6Running, "ipv4ConfigVerified": len(v4) > 0 && v4Verified, "ipv6ConfigVerified": false, "nativeIPv4": native, "forwardingTested": false, "message": "native relay process presence does not prove per-VLAN destination consumption; IPv6 destination changes require explicit service restart"})
	return v4Verified && v6Verified, observed, nil
}
