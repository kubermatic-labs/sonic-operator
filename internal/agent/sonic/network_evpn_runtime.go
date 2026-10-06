// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Exact installed SONiC 202511 consumer/schema reviewed read-only. A different
// build must be reviewed before extending this allowlist. This is software
// compatibility evidence ONLY, never a claim about the switch's SAI capability.
const evpnFRRHash = "5f01eac72568c1f2483621d61cbeb8d98abf5ddad632ac2cf23377c237a4b9a8"
const evpnYANGHash = "827c1321e96690d9d49c3f8893f48bedaf00523c93a6ef36e24e08f9a26a1d90"

type evpnCommandRunnerKey struct{}
type evpnCommandRunner func(*exec.Cmd) ([]byte, error)

func evpnRead(ctx context.Context, program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.WaitDelay = time.Second
	if run, ok := ctx.Value(evpnCommandRunnerKey{}).(evpnCommandRunner); ok {
		data, err := run(cmd)
		if slices.Contains(args, "supervisorctl") {
			err = evpnSupervisorError(data, err)
		}
		return data, err
	}
	var out routingBoundedOutput
	cmd.Stdout = &out
	err := cmd.Run()
	if slices.Contains(args, "supervisorctl") {
		err = evpnSupervisorError(out.buffer.Bytes(), err)
	}
	if err != nil {
		return nil, fmt.Errorf("EVPN read-only probe failed: %w", err)
	}
	return out.buffer.Bytes(), nil
}

func evpnSupervisorError(data []byte, err error) error {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		return err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || seen[f[0]] {
			return err
		}
		seen[f[0]] = true
		if f[1] == "RUNNING" {
			continue
		}
		if f[1] != "EXITED" || !slices.Contains([]string{"dependent-startup", "zsocket", "vtysh_b", "enable_counters", "gearsyncd", "restore_neighbors", "swssconfig", "wait_for_link"}, f[0]) {
			return err
		}
	}
	if len(seen) == 0 {
		return err
	}
	return nil
}

func evpnNative(ctx context.Context) error {
	for _, probe := range []struct{ container, path, hash string }{
		{"bgp", "/usr/local/lib/python3.11/dist-packages/frrcfgd/frrcfgd.py", evpnFRRHash},
		{"swss", "/usr/local/yang-models/sonic-vxlan.yang", evpnYANGHash},
	} {
		data, err := evpnRead(ctx, "docker", "exec", probe.container, "sha256sum", probe.path)
		if err != nil {
			return err
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 || fields[0] != probe.hash || fields[1] != probe.path {
			return fmt.Errorf("unreviewed native EVPN consumer/schema; unsupported release")
		}
	}
	version, err := evpnRead(ctx, "docker", "exec", "bgp", "vtysh", "-c", "show version")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(version), "FRRouting 10.4.1 ") {
		return fmt.Errorf("unreviewed FRR EVPN version")
	}
	for _, container := range []string{"bgp", "swss"} {
		data, err := evpnRead(ctx, "docker", "exec", container, "supervisorctl", "status")
		if err != nil {
			return err
		}
		running := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				running[f[0]] = f[1] == "RUNNING"
			}
		}
		needed := []string{"frrcfgd", "bgpd", "zebra"}
		if container == "swss" {
			needed = []string{"orchagent", "vxlanmgrd"}
		}
		for _, name := range needed {
			if !running[name] {
				return fmt.Errorf("native EVPN consumer %s must be running", name)
			}
		}
	}
	return nil
}

func evpnUnderlay(ctx context.Context, db vlanChangeDB, source, peer string) error {
	a, err := netip.ParseAddr(source)
	if err != nil {
		return err
	}
	iface, err := evpnLocalInterface(db, a)
	if err != nil {
		return err
	}
	family := "-4"
	if a.Is6() {
		family = "-6"
	}
	raw, err := evpnRead(ctx, "ip", "-j", family, "address", "show", "dev", iface)
	if err != nil {
		return err
	}
	var links []struct {
		Name      string   `json:"ifname"`
		Flags     []string `json:"flags"`
		Master    string   `json:"master"`
		Addresses []struct {
			Local string `json:"local"`
			Scope string `json:"scope"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(raw, &links) != nil || len(links) != 1 || links[0].Name != iface || links[0].Master != "" || !slices.Contains(links[0].Flags, "UP") {
		return fmt.Errorf("source interface is not operational in default VRF")
	}
	found := false
	for _, address := range links[0].Addresses {
		if address.Local == source && address.Scope == "global" {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("configured source is absent from actual local interface")
	}
	peers := []string{}
	if peer != "" {
		peers = append(peers, peer)
	} else {
		for key := range db {
			if !strings.HasPrefix(key, "BGP_NEIGHBOR|default|") {
				continue
			}
			p := strings.TrimPrefix(key, "BGP_NEIGHBOR|default|")
			addr, err := routingAddress(p, nil)
			if err == nil && addr.Is4() == a.Is4() && addr != a {
				peers = append(peers, addr.String())
			}
		}
	}
	if len(peers) == 0 {
		return fmt.Errorf("source-specific underlay check requires an existing BGP peer")
	}
	slices.Sort(peers)
	for _, destination := range peers {
		// Separate argv, validated addresses, and explicit source; a management
		// default route or a route found with a different source is insufficient.
		raw, err := evpnRead(ctx, "ip", "-j", family, "route", "get", destination, "from", source)
		if err != nil {
			return err
		}
		var routes []struct {
			Dev   string   `json:"dev"`
			Type  string   `json:"type"`
			From  string   `json:"from"`
			Flags []string `json:"flags"`
		}
		if json.Unmarshal(raw, &routes) != nil || len(routes) != 1 {
			return fmt.Errorf("source-specific route evidence unavailable")
		}
		r := routes[0]
		if !evpnInterface.MatchString(r.Dev) || strings.HasPrefix(r.Dev, "Loopback") || r.From != source || (r.Type != "" && r.Type != "unicast") || slices.Contains(r.Flags, "linkdown") {
			return fmt.Errorf("underlay must use an operational data-plane route from the configured source")
		}
		table := "INTERFACE|"
		base := "PORT|"
		if strings.HasPrefix(r.Dev, "PortChannel") {
			table, base = "PORTCHANNEL_INTERFACE|", "PORTCHANNEL|"
		}
		vrf := db[table+r.Dev]["vrf_name"]
		if db[base+r.Dev]["admin_status"] != "up" || (vrf != "" && vrf != "default") {
			return fmt.Errorf("underlay egress must be configured Up in default VRF")
		}
		data, err := evpnRead(ctx, "ip", "-j", "link", "show", "dev", r.Dev)
		if err != nil {
			return err
		}
		var egress []struct {
			Name  string   `json:"ifname"`
			State string   `json:"operstate"`
			Flags []string `json:"flags"`
		}
		if json.Unmarshal(data, &egress) != nil || len(egress) != 1 || egress[0].Name != r.Dev || egress[0].State != "UP" || !slices.Contains(egress[0].Flags, "LOWER_UP") {
			return fmt.Errorf("underlay egress has no actual carrier")
		}
	}
	return nil
}

type evpnFRR struct {
	global map[string]bool
	vnis   map[string][]string
	af     map[string]bool
}

// Parse the actual default FRR instance, preserving AF/VNI nesting. Unscoped
// string matching would accept an RD from another VNI or shutdown from a VRF.
func evpnFRRParse(config []byte, db vlanChangeDB) (*evpnFRR, error) {
	r := &evpnFRR{global: map[string]bool{}, vnis: map[string][]string{}, af: map[string]bool{}}
	inside, found, af, vni := false, false, "", ""
	root := "router bgp " + db["BGP_GLOBALS|default"]["local_asn"]
	for _, line := range strings.Split(string(config), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "router bgp ") {
			inside = l == root || l == root+" vrf default"
			if inside && found {
				return nil, fmt.Errorf("ambiguous default FRR BGP instance")
			}
			found = found || inside
			af, vni = "", ""
			continue
		}
		if !inside {
			continue
		}
		if l == "" || (l == "!" && line != l) {
			continue
		}
		if line == l {
			inside = false
			continue
		}
		if strings.HasPrefix(l, "address-family ") {
			af = strings.TrimPrefix(l, "address-family ")
			vni = ""
			continue
		}
		if l == "exit-address-family" {
			af, vni = "", ""
			continue
		}
		if af == "" {
			r.global[l] = true
			continue
		}
		if af != "l2vpn evpn" {
			continue
		}
		if strings.HasPrefix(l, "vni ") {
			if vni != "" {
				return nil, fmt.Errorf("invalid nested FRR VNI")
			}
			vni = strings.TrimPrefix(l, "vni ")
			if _, exists := r.vnis[vni]; exists {
				return nil, fmt.Errorf("duplicate FRR VNI")
			}
			r.vnis[vni] = []string{}
			continue
		}
		if l == "exit-vni" {
			vni = ""
			continue
		}
		if vni != "" {
			if !strings.HasPrefix(l, "rd ") && !strings.HasPrefix(l, "route-target import ") && !strings.HasPrefix(l, "route-target export ") && !strings.HasPrefix(l, "route-target both ") {
				return nil, fmt.Errorf("unsupported FRR VNI policy (L2 RD/RT only)")
			}
			r.vnis[vni] = append(r.vnis[vni], l)
		} else {
			if evpnOperationalAFLine(db, l) {
				if r.af[l] {
					return nil, fmt.Errorf("duplicate EVPN AF line")
				}
				r.af[l] = true
				continue
			}
			// Disabled neighbor AFs can be printed explicitly; no advertisement,
			// global RT, route-reflection, default origination, or active neighbors.
			f := strings.Fields(l)
			if len(f) != 4 || f[0] != "no" || f[1] != "neighbor" || f[3] != "activate" {
				return nil, fmt.Errorf("FRR EVPN export isolation not verified: active or unsupported AF policy")
			}
			r.af[l] = true
		}
	}
	if !found || !r.global["bgp default shutdown"] || !r.global["no bgp default ipv4-unicast"] || !r.global["bgp router-id "+db["BGP_GLOBALS|default"]["router_id"]] {
		return nil, fmt.Errorf("actual FRR ASN/routerID/safe defaults not verified")
	}
	for line := range r.global {
		if strings.Contains(line, "peer-group") || strings.Contains(line, "bgp listen") {
			return nil, fmt.Errorf("inherited/dynamic FRR peers unsupported")
		}
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "neighbor" && !r.global["neighbor "+f[1]+" shutdown"] {
			if db["BGP_NEIGHBOR|default|"+f[1]]["admin_status"] != "up" {
				return nil, fmt.Errorf("actual FRR neighbors must be shutdown while staging EVPN")
			}
			if _, err := evpnConfiguredPeerPolicy(db, f[1]); err != nil {
				return nil, err
			}
		}
		if len(f) >= 4 && f[0] == "no" && f[1] == "neighbor" && f[3] == "shutdown" {
			if db["BGP_NEIGHBOR|default|"+f[2]]["admin_status"] != "up" {
				return nil, fmt.Errorf("actual FRR neighbor is enabled")
			}
		}
	}
	for key, row := range db {
		if strings.HasPrefix(key, "BGP_NEIGHBOR_AF|default|") && strings.HasSuffix(key, "|"+evpnAF) && row["route_map_in@"] != "" {
			peer := strings.Split(key, "|")[2]
			policy, err := evpnConfiguredPeerPolicy(db, peer)
			if err != nil {
				return nil, err
			}
			if err := evpnVerifyPeerPolicy(config, db["BGP_GLOBALS|default"]["local_asn"], peer, policy); err != nil {
				return nil, err
			}
			if row["admin_status"] == "up" && !r.af["neighbor "+peer+" activate"] {
				return nil, fmt.Errorf("EVPN AF not activated")
			}
		}
	}
	return r, nil
}

func evpnOperationalAFLine(db vlanChangeDB, line string) bool {
	if line == "advertise-all-vni" {
		return evpnGlobalConfigValid(db[evpnGlobalKey]) && db[evpnGlobalKey]["advertise-all-vni"] == "true"
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "neighbor" {
		return false
	}
	p, err := evpnConfiguredPeerPolicy(db, f[1])
	if err != nil {
		return false
	}
	row := db["BGP_NEIGHBOR_AF|default|"+f[1]+"|"+evpnAF]
	if p.Transit && line == "neighbor "+f[1]+" attribute-unchanged next-hop" {
		return true
	}
	return (line == "neighbor "+f[1]+" activate" && row["admin_status"] == "up") || line == "neighbor "+f[1]+" route-map "+p.In+" in" || line == "neighbor "+f[1]+" route-map "+p.Out+" out" || line == "neighbor "+f[1]+" send-community extended"
}

func evpnFRRVNI(config []byte, asn string, s evpnMapSpec, required bool) error {
	// Parse instance/VNI here independently of defaults (checked by preflight).
	inside, af, vni := false, false, ""
	actual := []string{}
	found := false
	for _, line := range strings.Split(string(config), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "router bgp ") {
			inside = l == "router bgp "+asn || l == "router bgp "+asn+" vrf default"
			af = false
			vni = ""
			continue
		}
		if !inside {
			continue
		}
		if l == "" || (l == "!" && line != l) {
			continue
		}
		if line == l {
			inside = false
			continue
		}
		if strings.HasPrefix(l, "address-family ") {
			af = l == "address-family l2vpn evpn"
			vni = ""
			continue
		}
		if l == "exit-address-family" {
			af = false
			continue
		}
		if !af {
			continue
		}
		if strings.HasPrefix(l, "vni ") {
			vni = strings.TrimPrefix(l, "vni ")
			if vni == strconv.FormatUint(uint64(s.VNI), 10) {
				if found {
					return fmt.Errorf("duplicate runtime VNI")
				}
				found = true
			}
			continue
		}
		if l == "exit-vni" {
			vni = ""
			continue
		}
		if vni != strconv.FormatUint(uint64(s.VNI), 10) {
			continue
		}
		if strings.HasPrefix(l, "route-target both ") {
			rt := strings.TrimPrefix(l, "route-target both ")
			actual = append(actual, "route-target import "+rt, "route-target export "+rt)
		} else {
			actual = append(actual, l)
		}
	}
	if !found {
		if required {
			return fmt.Errorf("VNI absent from actual FRR")
		}
		return nil
	}
	want := []string{"rd " + s.RouteDistinguisher}
	for _, rt := range s.ImportRouteTargets {
		want = append(want, "route-target import "+rt)
	}
	for _, rt := range s.ExportRouteTargets {
		want = append(want, "route-target export "+rt)
	}
	slices.Sort(want)
	slices.Sort(actual)
	if !slices.Equal(want, actual) {
		return fmt.Errorf("actual FRR VNI RD/RT differs; no additive repair of unknown export policy")
	}
	return nil
}

func evpnPeerFRR(ctx context.Context, db vlanChangeDB, s evpnPeerSpec) error {
	data, err := runRoutingRead(ctx, routingBGPDaemons)
	if err != nil {
		return err
	}
	running := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 1 {
			running[f[0]] = f[1] == "RUNNING"
		}
	}
	if !running["frrcfgd"] || !running["bgpd"] {
		return fmt.Errorf("FRR consumer not running")
	}
	config, err := runRoutingRead(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	r, err := evpnFRRParse(config, db)
	if err != nil {
		return err
	}
	for _, suffix := range []string{"remote-as " + strconv.FormatUint(uint64(s.RemoteASN), 10), "update-source " + s.LocalAddress, "shutdown"} {
		if !r.global["neighbor "+s.Address+" "+suffix] {
			return fmt.Errorf("actual staged FRR neighbor identity/shutdown missing")
		}
	}
	return nil
}
