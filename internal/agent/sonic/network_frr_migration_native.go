// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type frrMigrationCommand int

const (
	frrMigrationConfig frrMigrationCommand = iota
	frrMigrationDaemons
	frrMigrationSummary
	frrMigrationNeighbors
	frrMigrationRoutes4
	frrMigrationRoutes6
	frrMigrationKernel4
	frrMigrationKernel6
	frrMigrationService
	frrMigrationCandidate
	frrMigrationInputs
	frrMigrationStartup
	frrMigrationRestart
	frrMigrationContainer
	frrMigrationSeparatedCandidate
	frrMigrationAddresses
)

// Fixed commands only. No spec field, approval, hostname or DB content is ever
// interpolated into a shell/program. Candidate rendering prints to stdout only.
func runFRRMigration(ctx context.Context, command frrMigrationCommand) ([]byte, error) {
	var argv []string
	switch command {
	case frrMigrationConfig:
		argv = []string{"docker", "exec", "bgp", "vtysh", "-c", "show running-config"}
	case frrMigrationDaemons:
		argv = []string{"docker", "exec", "bgp", "supervisorctl", "status"}
	case frrMigrationSummary:
		argv = []string{"docker", "exec", "bgp", "vtysh", "-c", "show bgp vrf all summary json"}
	case frrMigrationNeighbors:
		argv = []string{"docker", "exec", "bgp", "vtysh", "-c", "show bgp vrf all neighbors json"}
	case frrMigrationRoutes4:
		argv = []string{"docker", "exec", "bgp", "vtysh", "-c", "show ip route vrf all json"}
	case frrMigrationRoutes6:
		argv = []string{"docker", "exec", "bgp", "vtysh", "-c", "show ipv6 route vrf all json"}
	case frrMigrationKernel4:
		argv = []string{"ip", "-j", "-4", "route", "show", "table", "all"}
	case frrMigrationKernel6:
		argv = []string{"ip", "-j", "-6", "route", "show", "table", "all"}
	case frrMigrationAddresses:
		argv = []string{"ip", "-j", "address", "show"}
	case frrMigrationService:
		argv = []string{"systemctl", "show", "bgp.service", "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "InvocationID"}
	case frrMigrationCandidate:
		argv = []string{"docker", "exec", "bgp", "python3", "-c", frrMigrationRenderUnifiedScript}
	case frrMigrationSeparatedCandidate:
		argv = []string{"docker", "exec", "bgp", "python3", "-c", frrMigrationRenderSeparatedScript}
	case frrMigrationInputs:
		argv = []string{"docker", "exec", "bgp", "python3", "-c", frrMigrationInputsScript}
	case frrMigrationStartup:
		argv = []string{"docker", "exec", "bgp", "python3", "-c", frrMigrationStartupScript}
	case frrMigrationRestart:
		argv = []string{"systemctl", "restart", "bgp.service"}
	case frrMigrationContainer:
		argv = []string{"docker", "inspect", "--format", `{"id":{{json .Id}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}`, "bgp"}
	default:
		return nil, fmt.Errorf("unsupported FRR migration probe")
	}
	timeout := 8 * time.Second
	if command == frrMigrationRestart {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.WaitDelay = time.Second
	var output []byte
	var err error
	if run, ok := ctx.Value(routingCommandRunnerKey{}).(routingCommandRunner); ok {
		output, err = run(cmd)
	} else {
		var stdout routingBoundedOutput
		cmd.Stdout = &stdout
		err = cmd.Run()
		output = stdout.buffer.Bytes()
	}
	// Even fixture/execution errors may contain FRR passwords. Fixed errors only.
	var exitErr *exec.ExitError
	if command == frrMigrationDaemons && errors.As(err, &exitErr) && exitErr.ExitCode() == 3 && frrMigrationSupervisorReport(output) {
		err = nil
	}
	if err != nil || ctx.Err() != nil || len(output) > 4<<20 {
		return nil, frrMigrationCommandReason(command)
	}
	return output, nil
}

// sonic-cfggen loads -d AFTER -a on this image. Override a read-only JSON
// snapshot in memory, then render via stdin, never a temporary switch file.
// Use the exact docker_init.sh templates and search paths for each mode.
const frrMigrationRenderScript = `import subprocess,json
data=json.loads(subprocess.check_output(['sonic-cfggen','-d','--print-data']))
data['DEVICE_METADATA']['localhost'].update(frr_mgmt_framework_config=framework,docker_routing_config_mode=mode)
result={}
for name,template in templates.items():
    argv=['sonic-cfggen','-j','/dev/stdin','-y','/etc/sonic/constants.yml']
    if mode=='unified': argv+=['-T','/usr/local/sonic/frrcfgd']
    argv+=['-t','/usr/share/sonic/templates/'+template]
    result[name]=subprocess.check_output(argv,input=json.dumps(data).encode()).decode()
if mode=='unified': print(result['frr.conf'],end='')
else: print(json.dumps(result,sort_keys=True))`

const frrMigrationRenderUnifiedScript = "framework='true'; mode='unified'; templates={'frr.conf':'gen_frr.conf.j2'}\n" + frrMigrationRenderScript
const frrMigrationRenderSeparatedScript = "framework='false'; mode='separated'; templates={'bgpd.conf':'bgpd/gen_bgpd.conf.j2','zebra.conf':'zebra/zebra.conf.j2','staticd.conf':'staticd/gen_staticd.conf.j2'}\n" + frrMigrationRenderScript

func frrMigrationRender(ctx context.Context, mode string) ([]byte, error) {
	if mode == "Traditional" {
		return runFRRMigration(ctx, frrMigrationSeparatedCandidate)
	}
	return runFRRMigration(ctx, frrMigrationCandidate)
}

// Includes the actual init script and all recursively included templates, plus
// constants and controller binary. Values are hashed on-device, never returned.
const frrMigrationInputsScript = `import pathlib,hashlib,json
paths=[pathlib.Path('/usr/bin/docker_init.sh'),pathlib.Path('/etc/sonic/constants.yml'),pathlib.Path('/usr/local/bin/frrcfgd')]
for root in ['/usr/share/sonic/templates','/usr/local/sonic/frrcfgd']:
    paths.extend(p for p in pathlib.Path(root).rglob('*') if p.is_file())
assert len(paths)>3
result={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
print(hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest())`

// Full private backups are separate from the engine journal and safe receipt.
// This is a read-only command; writing backup.json happens locally on the agent.
const frrMigrationStartupScript = `import pathlib,json,base64
names=['bgpd.conf','zebra.conf','staticd.conf','frr.conf','vtysh.conf','bfdd.conf','ospfd.conf','pimd.conf','sharpd.conf']
result={}
for name in names:
    p=pathlib.Path('/etc/frr')/name
    result[name]=base64.b64encode(p.read_bytes()).decode() if p.exists() else None
print(json.dumps(result,sort_keys=True))`

type frrMigrationEvidence struct {
	StartHash     string `json:"startHash"`
	ContainerHash string `json:"containerHash"`
	ConfigHash    string `json:"configHash"`
	CandidateHash string `json:"candidateHash"`
	InputsHash    string `json:"inputsHash"`
	StartupHash   string `json:"startupHash"`
	// Route output contains uptime/counters. Validate it, but bind only semantic
	// state; full raw output would make an approval expire every second.
	RoutesHash string          `json:"routesHash"`
	Startup    json.RawMessage `json:"-"`
	Config     string          `json:"-"`
}

func frrMigrationDigest(db vlanChangeDB, evidence frrMigrationEvidence, mode ...string) string {
	data, _ := json.Marshal(struct {
		Version string
		DBHash  string
		Target  vlanChangeDB
		Runtime frrMigrationEvidence
	}{"empty-frr-migration-v1", vlanAuthorityHash(db), frrMigrationDesired(mode...), evidence})
	return vlanChangeHash(data)
}

func frrMigrationStart(data []byte) (string, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || fields[key] != "" {
			return "", fmt.Errorf("invalid BGP service evidence")
		}
		fields[key] = value
	}
	if len(fields) != 4 || fields["ActiveState"] != "active" || fields["SubState"] != "running" || fields["Result"] != "success" || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(fields["InvocationID"]) {
		return "", fmt.Errorf("BGP service not successfully running")
	}
	return vlanChangeHash([]byte(fields["InvocationID"])), nil
}

func frrMigrationContainerStart(ctx context.Context) (string, error) {
	data, err := runFRRMigration(ctx, frrMigrationContainer)
	if err != nil {
		return "", err
	}
	var container struct {
		ID        string `json:"id"`
		Running   bool   `json:"running"`
		StartedAt string `json:"startedAt"`
	}
	if json.Unmarshal(data, &container) != nil || !container.Running || !vlanAuthorityDigestValid(container.ID) {
		return "", fmt.Errorf("invalid BGP container identity")
	}
	start, err := time.Parse(time.RFC3339Nano, container.StartedAt)
	if err != nil || start.IsZero() {
		return "", fmt.Errorf("invalid BGP container start")
	}
	return vlanChangeHash([]byte(container.ID + "/" + container.StartedAt)), nil
}

func frrMigrationDaemonReady(data []byte, unified bool) bool {
	if !frrMigrationSupervisorReport(data) {
		return false
	}
	states := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || states[f[0]] != "" {
			return false
		}
		states[f[0]] = f[1]
	}
	for _, daemon := range []string{"zebra", "bgpd", "staticd", "fpmsyncd"} {
		if states[daemon] != "RUNNING" {
			return false
		}
	}
	if unified {
		return states["frrcfgd"] == "RUNNING" && states["bgpcfgd"] == ""
	}
	return states["bgpcfgd"] == "RUNNING" && states["frrcfgd"] == ""
}

// supervisorctl status exits 3 for any non-RUNNING process, including SONiC's
// completed one-shot helpers. Accept only a fully parsed report with those
// specific EXITED helpers; required routing daemons are checked separately.
func frrMigrationSupervisorReport(data []byte) bool {
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || seen[fields[0]] {
			return false
		}
		seen[fields[0]] = true
		if fields[1] == "RUNNING" {
			continue
		}
		if fields[1] != "EXITED" {
			return false
		}
		switch fields[0] {
		case "dependent-startup", "zsocket", "vtysh_b":
		default:
			return false
		}
	}
	return len(seen) > 0
}

// Exact allowlist from SONiC202511/FRR10.4.1. In particular, do not accept all
// "no ..." commands or arbitrary interface/router stanzas as harmless defaults.
func frrMigrationEmptyConfig(data []byte, hostname string) error {
	foundHost, foundAgent := false, false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		if line == "hostname "+hostname && hostname != "" {
			foundHost = true
			continue
		}
		switch line {
		case "Building configuration...", "Current configuration:", "frr version 10.4.1", "frr defaults traditional", "log syslog informational", "log facility local4", "zebra nexthop-group keep 1", "fpm address 127.0.0.1", "no fpm use-next-hop-groups", "no service integrated-vtysh-config", "service integrated-vtysh-config", "ip nht resolve-via-default", "ipv6 nht resolve-via-default", "end", "password zebra", "enable password zebra":
		case "agentx":
			foundAgent = true
		default:
			return fmt.Errorf("FRR configuration differs from supported empty baseline")
		}
	}
	if !foundHost || !foundAgent {
		return fmt.Errorf("FRR empty baseline incomplete")
	}
	return nil
}

// Unified SONiC starts pathd, whose FRR10.4.1 config writer emits this empty
// hierarchy even when no SR-TE configuration exists. Recognize exactly one
// complete, correctly nested block in running config only. Its child commands,
// other SR modes, standalone exits and candidate/traditional blocks remain
// subject to the strict allowlist; never allow these tokens independently.
func frrMigrationEmptyRuntimeConfig(data []byte, hostname string, unified bool) error {
	if unified {
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if line != "segment-routing" {
				continue
			}
			if i+3 < len(lines) && lines[i+1] == " traffic-eng" && lines[i+2] == " exit" && lines[i+3] == "exit" {
				lines = append(lines[:i], lines[i+4:]...)
				data = []byte(strings.Join(lines, "\n"))
			}
			break
		}
	}
	return frrMigrationEmptyConfig(data, hostname)
}

func frrMigrationEmptyJSON(data []byte) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(data, &object) == nil && object != nil && len(object) == 0
}

func frrMigrationModeReady(ctx context.Context, mode ...string) (bool, error) {
	service, err := runFRRMigration(ctx, frrMigrationService)
	if err != nil {
		return false, err
	}
	if _, err = frrMigrationStart(service); err != nil {
		return false, err
	}
	daemons, err := runFRRMigration(ctx, frrMigrationDaemons)
	if err != nil {
		return false, err
	}
	return frrMigrationDaemonReady(daemons, frrMigrationMode(mode...) == "Unified"), nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func inspectFRRMigration(ctx context.Context, db vlanChangeDB, modes ...string) (evidence frrMigrationEvidence, resultErr error) {
	mode := frrMigrationMode(modes...)
	stage := frrMigrationDiagnostic("ConfigDBNotEmptyOrUnsupported")
	defer func() {
		if resultErr != nil {
			var diagnostic frrMigrationDiagnostic
			if !errors.As(resultErr, &diagnostic) {
				resultErr = stage
			}
		}
	}()
	if err := frrMigrationEmptyDB(db); err != nil {
		return evidence, err
	}
	if !frrMigrationTraditional(db) && !networkSubset(db, frrMigrationDesired()) {
		return evidence, fmt.Errorf("unsupported source mode")
	}
	stage = "ServiceNotReady"
	service, err := runFRRMigration(ctx, frrMigrationService)
	if err != nil {
		return evidence, err
	}
	evidence.StartHash, err = frrMigrationStart(service)
	if err != nil {
		return evidence, err
	}
	stage = "ContainerNotReady"
	evidence.ContainerHash, err = frrMigrationContainerStart(ctx)
	if err != nil {
		return evidence, err
	}
	stage = "RoutingDaemonsNotReady"
	daemons, err := runFRRMigration(ctx, frrMigrationDaemons)
	if err != nil {
		return evidence, err
	}
	if !frrMigrationDaemonReady(daemons, networkSubset(db, frrMigrationDesired())) {
		return evidence, fmt.Errorf("FRR controller or routing daemons not ready")
	}
	stage = "RunningConfigNotEmpty"
	config, err := runFRRMigration(ctx, frrMigrationConfig)
	if err != nil {
		return evidence, err
	}
	if err = frrMigrationEmptyRuntimeConfig(config, db["DEVICE_METADATA|localhost"]["hostname"], networkSubset(db, frrMigrationDesired())); err != nil {
		return evidence, err
	}
	evidence.ConfigHash, evidence.Config = vlanChangeHash(config), string(config)
	for _, command := range []frrMigrationCommand{frrMigrationSummary, frrMigrationNeighbors} {
		stage = "BGPInstancesOrPeersNotEmpty"
		data, err := runFRRMigration(ctx, command)
		if err != nil {
			return evidence, err
		}
		if !frrMigrationEmptyJSON(data) {
			return evidence, fmt.Errorf("FRR BGP instances or peers not empty")
		}
	}
	var routes []string
	var hostEvidence frrMigrationHostEvidence
	for _, command := range []frrMigrationCommand{frrMigrationRoutes4, frrMigrationRoutes6, frrMigrationKernel4, frrMigrationKernel6} {
		stage = map[frrMigrationCommand]frrMigrationDiagnostic{frrMigrationRoutes4: "FRRIPv4RoutesUnsupported", frrMigrationRoutes6: "FRRIPv6RoutesUnsupported", frrMigrationKernel4: "KernelIPv4RoutesUnsupported", frrMigrationKernel6: "KernelIPv6RoutesUnsupported"}[command]
		data, err := runFRRMigration(ctx, command)
		if err != nil {
			return evidence, err
		}
		semantic, err := frrMigrationValidateRoutes(data, command == frrMigrationKernel4 || command == frrMigrationKernel6, db)
		if err != nil {
			if hostEvidence == nil {
				addresses, probeErr := runFRRMigration(ctx, frrMigrationAddresses)
				if probeErr != nil {
					return evidence, fmt.Errorf("host address corroboration unavailable")
				}
				hostEvidence, probeErr = frrMigrationHostAddresses(addresses, db)
				if probeErr != nil {
					return evidence, probeErr
				}
			}
			semantic, err = frrMigrationValidateRoutes(data, command == frrMigrationKernel4 || command == frrMigrationKernel6, db, hostEvidence)
		}
		if err != nil {
			return evidence, err
		}
		routes = append(routes, semantic)
	}
	if hostEvidence != nil {
		addresses, err := runFRRMigration(ctx, frrMigrationAddresses)
		if err != nil {
			return evidence, err
		}
		after, err := frrMigrationHostAddresses(addresses, db)
		if err != nil || after.semantic() != hostEvidence.semantic() {
			return evidence, fmt.Errorf("host addresses changed during routing verification")
		}
		routes = append(routes, hostEvidence.semantic())
	}
	data, _ := json.Marshal(routes)
	evidence.RoutesHash = vlanChangeHash(data)
	stage = "CandidateNotEmpty"
	candidate, err := frrMigrationRender(ctx, mode)
	if err != nil {
		return evidence, err
	}
	if err = frrMigrationValidateCandidate(candidate, db["DEVICE_METADATA|localhost"]["hostname"], mode); err != nil {
		return evidence, fmt.Errorf("generated candidate is not supported empty routing")
	}
	evidence.CandidateHash = vlanChangeHash(candidate)
	stage = "TemplateInputsInvalid"
	inputs, err := runFRRMigration(ctx, frrMigrationInputs)
	if err != nil {
		return evidence, err
	}
	evidence.InputsHash = strings.TrimSpace(string(inputs))
	if !vlanAuthorityDigestValid(evidence.InputsHash) {
		return evidence, fmt.Errorf("invalid template/startup input evidence")
	}
	stage = "StartupFilesInvalid"
	startup, err := runFRRMigration(ctx, frrMigrationStartup)
	if err != nil {
		return evidence, err
	}
	var files map[string]*string
	if json.Unmarshal(startup, &files) != nil || len(files) != 9 || files["vtysh.conf"] == nil {
		return evidence, fmt.Errorf("invalid startup file snapshot")
	}
	for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf", "frr.conf", "vtysh.conf", "bfdd.conf", "ospfd.conf", "pimd.conf", "sharpd.conf"} {
		value, exists := files[name]
		if !exists {
			return evidence, fmt.Errorf("incomplete startup file snapshot")
		}
		if value != nil {
			if _, err := base64.StdEncoding.DecodeString(*value); err != nil {
				return evidence, fmt.Errorf("invalid startup file encoding")
			}
		}
	}
	if networkSubset(db, frrMigrationDesired()) {
		sourceCandidate := candidate
		if mode != "Unified" {
			sourceCandidate, err = frrMigrationRender(ctx, "Unified")
			if err != nil || frrMigrationEmptyConfig(sourceCandidate, db["DEVICE_METADATA|localhost"]["hostname"]) != nil {
				return evidence, fmt.Errorf("unified source candidate invalid")
			}
		}
		if files["frr.conf"] == nil {
			return evidence, fmt.Errorf("unified startup configuration missing")
		}
		generated, _ := base64.StdEncoding.DecodeString(*files["frr.conf"])
		vtysh, _ := base64.StdEncoding.DecodeString(*files["vtysh.conf"])
		if vlanChangeHash(generated) != vlanChangeHash(sourceCandidate) || strings.TrimSpace(string(vtysh)) != "service integrated-vtysh-config" {
			return evidence, fmt.Errorf("unified startup configuration differs from approved candidate")
		}
		for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf", "bfdd.conf", "ospfd.conf", "pimd.conf"} {
			if files[name] != nil {
				return evidence, fmt.Errorf("legacy startup files remain after unified activation")
			}
		}
	}
	if mode == "Traditional" && frrMigrationTraditional(db) {
		var generated map[string]string
		if json.Unmarshal(candidate, &generated) != nil {
			return evidence, fmt.Errorf("invalid separated candidate")
		}
		for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf"} {
			if files[name] == nil {
				return evidence, fmt.Errorf("separated startup file missing")
			}
			data, _ := base64.StdEncoding.DecodeString(*files[name])
			if string(data) != generated[name] {
				return evidence, fmt.Errorf("separated startup file differs from approved candidate")
			}
		}
		vtysh, _ := base64.StdEncoding.DecodeString(*files["vtysh.conf"])
		if strings.TrimSpace(string(vtysh)) != "no service integrated-vtysh-config" || files["frr.conf"] != nil || files["bfdd.conf"] != nil || files["ospfd.conf"] != nil || files["pimd.conf"] != nil {
			return evidence, fmt.Errorf("separated startup mode invalid")
		}
	}
	evidence.StartupHash, evidence.Startup = vlanChangeHash(startup), startup
	stage = "ServiceChangedDuringPreflight"
	end, err := runFRRMigration(ctx, frrMigrationService)
	if err != nil {
		return evidence, err
	}
	endHash, err := frrMigrationStart(end)
	if err != nil || endHash != evidence.StartHash {
		return evidence, fmt.Errorf("BGP service changed during preflight")
	}
	stage = "ContainerChangedDuringPreflight"
	endContainer, err := frrMigrationContainerStart(ctx)
	if err != nil || endContainer != evidence.ContainerHash {
		return evidence, fmt.Errorf("BGP container changed during preflight")
	}
	return evidence, nil
}

// Permit only management and fixed SONiC host plumbing. No forwarding-port
// connected routes, unknown tables, static FRR routes or protocol-learned routes.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func frrMigrationRouteAllowed(dst, dev, protocol, kind, gateway string, db vlanChangeDB, kernel bool) bool {
	if protocol != "connected" && !(kernel && (protocol == "kernel" || protocol == "" || protocol == "boot")) {
		return false
	}
	if kind != "" && kind != "unicast" && kind != "local" && kind != "broadcast" && kind != "anycast" && kind != "multicast" {
		return false
	}
	if dst == "default" {
		if !kernel || dev != "eth0" || gateway == "" {
			return false
		}
		for key, f := range db {
			if strings.HasPrefix(key, "MGMT_INTERFACE|eth0|") && f["gwaddr"] == gateway {
				return true
			}
		}
		return false
	}
	p, err := netip.ParsePrefix(dst)
	if err != nil {
		a, e := netip.ParseAddr(dst)
		if e != nil {
			return false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if gateway != "" {
		return false
	}
	a := p.Addr()
	switch dev {
	case "eth0":
		if a.Is6() && ((a.IsLinkLocalUnicast() && p.Bits() >= 64) || (kernel && dst == "ff00::/8")) {
			return true
		}
		for key := range db {
			if strings.HasPrefix(key, "MGMT_INTERFACE|eth0|") {
				mgmt, e := netip.ParsePrefix(strings.TrimPrefix(key, "MGMT_INTERFACE|eth0|"))
				if e == nil && mgmt.Masked().Contains(a) && p.Bits() >= mgmt.Bits() {
					return true
				}
			}
		}
	case "lo":
		return kernel && a.IsLoopback() && ((a.Is4() && p.Bits() >= 8) || (a.Is6() && p.Bits() == 128))
	case "docker0":
		return kernel && ((netip.MustParsePrefix("240.127.1.0/24").Contains(a) && p.Bits() >= 24) || (netip.MustParsePrefix("fd00::/80").Contains(a) && p.Bits() >= 80))
	case "Bridge", "dummy", "sr0":
		return a.Is6() && ((a.IsLinkLocalUnicast() && p.Bits() >= 64) || (kernel && dst == "ff00::/8"))
	}
	return false
}

func frrMigrationValidateRoutes(data []byte, kernel bool, db vlanChangeDB, host ...frrMigrationHostEvidence) (string, error) {
	fail := func() (string, error) { return "", fmt.Errorf("unsupported effective routing state") }
	allowed := func(dst, dev, protocol, kind, gateway string) bool {
		return frrMigrationRouteAllowed(dst, dev, protocol, kind, gateway, db, kernel) || len(host) == 1 && host[0].routeAllowed(dst, dev, protocol, kind, gateway, kernel)
	}
	var semantic []string
	if kernel {
		var rows []struct {
			Dst      string          `json:"dst"`
			Dev      string          `json:"dev"`
			Protocol string          `json:"protocol"`
			Type     string          `json:"type"`
			Gateway  string          `json:"gateway"`
			Table    json.RawMessage `json:"table"`
			Nexthops json.RawMessage `json:"nexthops"`
			Encap    json.RawMessage `json:"encap"`
		}
		if json.Unmarshal(data, &rows) != nil || rows == nil {
			return fail()
		}
		for _, r := range rows {
			table := string(r.Table)
			if table != "" && table != `"default"` && table != `"local"` && table != `"main"` && table != "253" && table != "254" && table != "255" {
				return fail()
			}
			if len(r.Nexthops) > 0 || len(r.Encap) > 0 || !allowed(r.Dst, r.Dev, r.Protocol, r.Type, r.Gateway) {
				return fail()
			}
			semantic = append(semantic, strings.Join([]string{r.Dst, r.Dev, r.Protocol, r.Type, r.Gateway, table}, "|"))
		}
	} else {
		var vrfs map[string]map[string][]struct {
			Prefix   string `json:"prefix"`
			Protocol string `json:"protocol"`
			Nexthops []struct {
				InterfaceName string `json:"interfaceName"`
				IP            string `json:"ip"`
			} `json:"nexthops"`
		}
		if json.Unmarshal(data, &vrfs) != nil || vrfs == nil {
			return fail()
		}
		for vrf, rows := range vrfs {
			if vrf != "default" || rows == nil {
				return fail()
			}
			for prefix, routes := range rows {
				if len(routes) == 0 {
					return fail()
				}
				for _, r := range routes {
					if r.Prefix != prefix || len(r.Nexthops) == 0 {
						return fail()
					}
					for _, hop := range r.Nexthops {
						if !allowed(prefix, hop.InterfaceName, r.Protocol, "", hop.IP) {
							return fail()
						}
						value := prefix + "|" + r.Protocol + "|" + hop.InterfaceName
						if hop.IP != "" {
							value += "|" + hop.IP
						}
						semantic = append(semantic, value)
					}
				}
			}
		}
	}
	// Stable order; uptime, netlink indices and FRR counters are not approvals.
	// Retain duplicates since multipath changes are semantically meaningful.
	sort.Strings(semantic)
	encoded, _ := json.Marshal(semantic)
	return string(encoded), nil
}
