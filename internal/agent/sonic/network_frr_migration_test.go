// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Sanitized actual show running-config from SONiC202511/FRR10.4.1 on
// leaf-03, read-only inspection 2026-09-12. Template password defaults are
// deliberately included: rejecting all password lines rejects the stock image.
const frrMigrationDefaultConfig = `Building configuration...

Current configuration:
!
frr version 10.4.1
frr defaults traditional
hostname leaf-03
password zebra
enable password zebra
log syslog informational
log facility local4
zebra nexthop-group keep 1
fpm address 127.0.0.1
no fpm use-next-hop-groups
agentx
no service integrated-vtysh-config
!
!
ip nht resolve-via-default
!
ipv6 nht resolve-via-default
!
end
`

const frrMigrationDefaultCandidate = `!
! =========== Managed by sonic-cfggen DO NOT edit manually! ====================
hostname leaf-03
password zebra
enable password zebra
log syslog informational
log facility local4
agentx
no fpm use-next-hop-groups
fpm address 127.0.0.1
ip nht resolve-via-default
ipv6 nht resolve-via-default
!
`

func frrMigrationTestDB() vlanChangeDB {
	return vlanChangeDB{
		"DEVICE_METADATA|localhost":       {"hostname": "leaf-03", "hwsku": "Force10-Z9100", "platform": "x86_64-dell_z9100_c2538-r0", "default_bgp_status": "up"},
		"BGP_DEVICE_GLOBAL|STATE":         {"idf_isolation_state": "unisolated", "tsa_enabled": "false", "wcmp_enabled": "false"},
		"MGMT_INTERFACE|eth0|10.0.0.10/8": {"gwaddr": "10.0.0.1"},
		"PORT|Ethernet0":                  {"admin_status": "up"},
	}
}

type frrMigrationFixture struct {
	restarts           int
	config             string
	candidate          string
	inputs             string
	summary            string
	neighbors          string
	kernel             string
	fresh              bool
	separated          bool
	separatedCandidate map[string]string
	uncertain          bool
	restartHook        func()
	readHook           func(*exec.Cmd)
}

func newFRRMigrationFixture() *frrMigrationFixture {
	return &frrMigrationFixture{config: frrMigrationDefaultConfig, candidate: frrMigrationDefaultCandidate, inputs: strings.Repeat("a", 64), summary: `{}`, neighbors: `{}`, kernel: `[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","table":"default","metric":201,"flags":[]},{"dst":"10.0.0.0/8","dev":"eth0","protocol":"kernel","scope":"link"},{"dst":"10.100.0.0/24","dev":"eth0","table":"default","scope":"link"},{"dst":"240.127.1.0/24","dev":"docker0","protocol":"kernel","scope":"link"},{"type":"local","dst":"127.0.0.1","dev":"lo","table":"local","protocol":"kernel"}]`}
}

func (f *frrMigrationFixture) run(cmd *exec.Cmd) ([]byte, error) {
	if f.readHook != nil {
		f.readHook(cmd)
	}
	args := strings.Join(cmd.Args, " ")
	switch {
	case strings.HasPrefix(args, "docker inspect "):
		start := "2026-09-12T13:31:00Z"
		if f.fresh {
			start = fmt.Sprintf("2026-09-12T17:31:%02dZ", f.restarts)
		}
		return []byte(fmt.Sprintf(`{"id":%q,"running":true,"startedAt":%q}`, strings.Repeat("a", 64), start)), nil
	case args == "systemctl restart bgp.service":
		f.restarts++
		f.fresh = true
		if f.restartHook != nil {
			f.restartHook()
		}
		if f.uncertain {
			return nil, fmt.Errorf("lost response secret-sensitive-output")
		}
		return nil, nil
	case strings.HasPrefix(args, "systemctl show "):
		id := strings.Repeat("1", 32)
		if f.fresh {
			id = fmt.Sprintf("%032x", f.restarts+2)
		}
		return []byte("Result=success\nActiveState=active\nSubState=running\nInvocationID=" + id + "\n"), nil
	case args == "docker exec bgp supervisorctl status":
		controller := "bgpcfgd"
		if f.fresh && !f.separated {
			controller = "frrcfgd"
		}
		return []byte(controller + " RUNNING pid 64, uptime 3:32:02\nbgpd RUNNING pid 57, uptime 3:32:03\nzebra RUNNING pid 43, uptime 3:32:03\nstaticd RUNNING pid 56, uptime 3:32:03\nfpmsyncd RUNNING pid 66, uptime 3:32:02\nmgmtd RUNNING pid 42, uptime 3:32:03\nzsocket EXITED Sep 12 01:31 PM\n"), nil
	case args == "docker exec bgp vtysh -c show running-config":
		config := f.config
		if f.fresh && !f.separated {
			config = strings.ReplaceAll(config, "no service integrated-vtysh-config", "service integrated-vtysh-config")
			config = strings.ReplaceAll(config, "end\n", frrMigrationEmptyPathd+"!\nend\n")
		}
		return []byte(config), nil
	case args == "docker exec bgp vtysh -c show bgp vrf all summary json":
		return []byte(f.summary), nil
	case args == "docker exec bgp vtysh -c show bgp vrf all neighbors json":
		return []byte(f.neighbors), nil
	case args == "docker exec bgp vtysh -c show ip route vrf all json":
		return []byte(`{"default":{"10.0.0.0/8":[{"prefix":"10.0.0.0/8","protocol":"connected","uptime":"02:41:48","nexthops":[{"interfaceName":"eth0","active":true}]}]}}`), nil
	case args == "docker exec bgp vtysh -c show ipv6 route vrf all json":
		return []byte(`{"default":{"fe80::/64":[{"prefix":"fe80::/64","protocol":"connected","nexthops":[{"interfaceName":"eth0"}]},{"prefix":"fe80::/64","protocol":"connected","nexthops":[{"interfaceName":"sr0"}]}]}}`), nil
	case args == "ip -j -4 route show table all":
		return []byte(f.kernel), nil
	case args == "ip -j -6 route show table all":
		return []byte(`[{"dst":"fd00::/80","dev":"docker0","protocol":"kernel"},{"dst":"fe80::/64","dev":"sr0","protocol":"kernel"},{"dst":"ff00::/8","type":"multicast","dev":"Bridge","table":"local","protocol":"kernel"}]`), nil
	case strings.HasPrefix(args, "docker exec bgp sonic-cfggen "):
		if !strings.Contains(args, "-T /usr/local/sonic/frrcfgd") || strings.Contains(args, ",/etc/") || strings.Contains(args, " -w") {
			return nil, fmt.Errorf("unsafe render")
		}
		return []byte(f.candidate), nil
	case len(cmd.Args) == 6 && cmd.Args[5] == frrMigrationInputsScript:
		return []byte(f.inputs), nil
	case len(cmd.Args) == 6 && cmd.Args[5] == frrMigrationRenderUnifiedScript:
		return []byte(f.candidate), nil
	case len(cmd.Args) == 6 && cmd.Args[5] == frrMigrationRenderSeparatedScript:
		return json.Marshal(f.separatedFiles())
	case len(cmd.Args) == 6 && cmd.Args[5] == frrMigrationStartupScript:
		files := map[string]*string{}
		content := base64.StdEncoding.EncodeToString([]byte("password secret-sensitive-output"))
		for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf", "frr.conf", "vtysh.conf", "bfdd.conf", "ospfd.conf", "pimd.conf", "sharpd.conf"} {
			files[name] = &content
		}
		if f.fresh && !f.separated {
			for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf", "bfdd.conf", "ospfd.conf", "pimd.conf"} {
				files[name] = nil
			}
			generated := base64.StdEncoding.EncodeToString([]byte(f.candidate))
			vtysh := base64.StdEncoding.EncodeToString([]byte("service integrated-vtysh-config\n"))
			files["frr.conf"], files["vtysh.conf"] = &generated, &vtysh
		}
		if f.separated {
			for _, name := range []string{"frr.conf", "bfdd.conf", "ospfd.conf", "pimd.conf"} {
				files[name] = nil
			}
			for name, data := range f.separatedFiles() {
				encoded := base64.StdEncoding.EncodeToString([]byte(data))
				files[name] = &encoded
			}
			vtysh := base64.StdEncoding.EncodeToString([]byte("no service integrated-vtysh-config\n"))
			files["vtysh.conf"] = &vtysh
		}
		return json.Marshal(files)
	default:
		return nil, fmt.Errorf("unexpected command")
	}
}

func (f *frrMigrationFixture) ctx(t *testing.T) context.Context {
	return context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(f.run))
}

func TestFRRMigrationPlan(t *testing.T) {
	t.Parallel()
	for _, spec := range []string{`{"mode":"Unified"}`, `{"switchRef":{"name":"switch"},"managementPolicy":"Control","mode":"Unified","approvedDigest":"` + strings.Repeat("a", 64) + `"}`} {
		t.Run(spec, func(t *testing.T) {
			r := &agent.NetworkRequest{Kind: "FRRMigration", OwnerID: "uid", Spec: json.RawMessage(spec)}
			pre, err := planNetworkResource(frrMigrationTestDB(), r)
			if err != nil {
				t.Fatal(err)
			}
			post, err := planNetworkResource(frrMigrationPost(frrMigrationTestDB()), r)
			if err != nil {
				t.Fatal(err)
			}
			if pre.Identity != frrMigrationIdentity || !reflect.DeepEqual(pre.Desired, frrMigrationDesired()) || !reflect.DeepEqual(pre.Desired, post.Desired) || pre.Preflight == nil || post.Activate == nil || post.Runtime == nil {
				t.Fatal("unstable migration contract")
			}
		})
	}
	for _, spec := range []string{`{}`, `{"mode":"unified"}`, `{"mode":"Unified","approvedDigest":"ABC"}`, `{"mode":"Unified","mode":"Unified"}`, `{"mode":null}`, `{"Mode":"Unified"}`, `{"mode":"Unified","command":"restart"}`, `{"mode":"Unified","approvedDigest":null}`} {
		t.Run("reject-"+spec, func(t *testing.T) {
			if _, err := planNetworkFRRMigration(nil, &agent.NetworkRequest{Kind: "FRRMigration", Spec: json.RawMessage(spec)}); err == nil {
				t.Fatal("accepted unsupported request")
			}
		})
	}
}

func TestFRRMigrationPreflightBaseline(t *testing.T) {
	t.Parallel()
	fixture := newFRRMigrationFixture()
	evidence, err := inspectFRRMigration(fixture.ctx(t), frrMigrationTestDB())
	if err != nil {
		t.Fatal(err)
	}
	digest := frrMigrationDigest(frrMigrationTestDB(), evidence)
	if !vlanAuthorityDigestValid(digest) {
		t.Fatal("invalid digest")
	}
	for _, test := range []struct {
		name   string
		change func(*frrMigrationFixture)
	}{
		{"router", func(f *frrMigrationFixture) { f.config += "router bgp 65000\n" }},
		{"unknown-no-command", func(f *frrMigrationFixture) { f.config += "no ip forwarding\n" }},
		{"secret", func(f *frrMigrationFixture) { f.config += "password secret-sensitive-output\n" }},
		{"missing-baseline", func(f *frrMigrationFixture) { f.config = "" }},
		{"candidate", func(f *frrMigrationFixture) { f.candidate += "ip route 0.0.0.0/0 10.0.0.1\n" }},
		{"neighbors", func(f *frrMigrationFixture) { f.neighbors = `{"default":{"192.0.2.1":{}}}` }},
		{"summary-null", func(f *frrMigrationFixture) { f.summary = `null` }},
		{"kernel-route", func(f *frrMigrationFixture) {
			f.kernel = `[{"dst":"192.0.2.0/24","dev":"Ethernet0","protocol":"kernel"}]`
		}},
		{"template-read", func(f *frrMigrationFixture) { f.inputs = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFRRMigrationFixture()
			test.change(f)
			if _, err := inspectFRRMigration(f.ctx(t), frrMigrationTestDB()); err == nil {
				t.Fatal("unsafe state eligible")
			} else if strings.Contains(err.Error(), "secret-sensitive-output") {
				t.Fatal("leaked raw config")
			}
		})
	}
}

func TestFRRMigrationEmptyDB(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"BGP_GLOBALS|default", "BGP_NEIGHBOR|192.0.2.1", "BGP_PEER_RANGE|range", "STATIC_ROUTE|0.0.0.0/0", "ROUTE_MAP|policy", "PREFIX_SET|filter", "VRF|VrfTest", "LOOPBACK_INTERFACE|Loopback0", "INTERFACE|Ethernet0", "PORTCHANNEL_INTERFACE|PortChannel1", "VLAN_INTERFACE|Vlan1", "BFD_PEER|x", "OSPF_ROUTER|default", "ISIS_GLOBAL|default", "PIM_GLOBAL|default", "VNET|vnet", "BGP_DEVICE_GLOBAL|unknown", "DEVICE_METADATA|asic0", "MGMT_VRF_CONFIG|vrf_global"} {
		t.Run(key, func(t *testing.T) {
			db := frrMigrationTestDB()
			db[key] = map[string]string{"NULL": "NULL"}
			if frrMigrationEmptyDB(db) == nil {
				t.Fatal("accepted routing placeholder")
			}
		})
	}
	for _, field := range []string{"bgp_asn", "type", "subtype", "nexthop_group", "peer_switch"} {
		t.Run(field, func(t *testing.T) {
			db := frrMigrationTestDB()
			db["DEVICE_METADATA|localhost"][field] = "enabled"
			if frrMigrationEmptyDB(db) == nil {
				t.Fatal("accepted automatic routing")
			}
		})
	}
}

func TestFRRMigrationRejectUnsafeFieldsAndRoutes(t *testing.T) {
	t.Parallel()
	for _, desired := range []vlanChangeDB{
		{},
		{"DEVICE_METADATA|localhost": {"frr_mgmt_framework_config": "true"}},
		{"DEVICE_METADATA|other": {"frr_mgmt_framework_config": "true", "docker_routing_config_mode": "unified"}},
		{"DEVICE_METADATA|localhost": {"frr_mgmt_framework_config": "true", "docker_routing_config_mode": "separated"}},
		{"DEVICE_METADATA|localhost": {"frr_mgmt_framework_config": "true", "docker_routing_config_mode": "unified", "bgp_asn": "65000"}},
	} {
		t.Run(fmt.Sprint(desired), func(t *testing.T) {
			if validateNetworkFields("FRRMigration", desired) == nil {
				t.Fatal("unsafe migration field allowlist")
			}
		})
	}
	for _, route := range []string{
		`null`,
		`[{"dst":"default","dev":"eth0","gateway":"192.0.2.1"}]`,
		`[{"dst":"10.0.0.0/8","dev":"eth0","protocol":"bgp"}]`,
		`[{"dst":"10.0.0.0/8","dev":"eth0","table":"unrecognized"}]`,
		`[{"dst":"127.0.0.1/0","dev":"lo","protocol":"kernel"}]`,
		`[{"dst":"fe80::/0","dev":"Bridge","protocol":"kernel"}]`,
		`[{"dst":"10.0.0.0/8","dev":"eth0","nexthops":[]}]`,
	} {
		t.Run(route, func(t *testing.T) {
			if _, err := frrMigrationValidateRoutes([]byte(route), true, frrMigrationTestDB()); err == nil {
				t.Fatal("unsafe effective route accepted")
			}
		})
	}
}
