// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const breakoutNativeTimeout = 120 * time.Second
const breakoutConvergenceTimeout = 30 * time.Second

// Suppress Python and native-library diagnostics: only fixed classification
// tokens cross the process boundary, never addresses, credentials or config.
const breakoutValidationPython = `
import os
result_fd = os.dup(1)
with open(os.devnull, 'w') as sink:
    os.dup2(sink.fileno(), 1)
    os.dup2(sink.fileno(), 2)
result = 'invalid'
try:
    from config.config_mgmt import ConfigMgmtDPB
    ConfigMgmtDPB()
    result = 'ok'
except Exception as error:
    messages = []
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        messages.append(str(error).lower())
        error = error.__cause__ or error.__context__
    detail = '\n'.join(messages)
    if 'mgmt_port' in detail and ('leafref' in detail or 'non-existing' in detail):
        result = 'mgmt_port'
    elif 'gwaddr' in detail:
        result = 'mgmt_gateway'
os.write(result_fd, (result + '\n').encode('ascii'))
os.close(result_fd)
`

func (m *SonicAgent) checkNativeBreakoutConfig(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("native CONFIG_DB validation canceled: %w", err)
	}
	if m.validateBreakoutConfig != nil {
		return m.validateBreakoutConfig(ctx)
	}
	cmd := exec.CommandContext(ctx, "python3", "-c", breakoutValidationPython)
	cmd.WaitDelay = time.Second
	out, err := m.executeBreakout(ctx, cmd)
	if ctx.Err() != nil {
		return fmt.Errorf("native CONFIG_DB validation canceled or deadline exceeded; no breakout intent recorded: %w", ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("native CONFIG_DB validation process failed; inspect local ConfigMgmt/YANG diagnostics before retry; no breakout intent recorded")
	}
	switch strings.TrimSpace(string(out)) {
	case "ok":
		return nil
	case "mgmt_port":
		return fmt.Errorf("native CONFIG_DB validation failed: MGMT_INTERFACE references a missing MGMT_PORT; inspect management port definitions and obtain operator approval before any correction; no breakout intent recorded")
	case "mgmt_gateway":
		return fmt.Errorf("native CONFIG_DB validation failed: management interface gwaddr requirement is invalid or missing; inspect legacy MGMT_INTERFACE entries and obtain operator approval before any correction; no breakout intent recorded")
	default:
		return fmt.Errorf("native CONFIG_DB validation failed: inspect local ConfigMgmt/YANG diagnostics and obtain operator approval before correcting configuration; no breakout intent recorded")
	}
}

// This is deliberately a fixed program, not a user-supplied command. SONiC's
// get_child_ports(interface, breakout_mode, platform_json_file) owns lane mapping.
const breakoutResolverPython = `
import copy, json, os, re, sys
from portconfig import get_child_ports
from sonic_py_common import device_info
from config.config_mgmt import ConfigMgmtDPB, YANG_DIR
from sonic_yang import SonicYang
from swsscommon.swsscommon import ConfigDBConnector
port, platform, hwsku, expected_root = sys.argv[1:]
for value in (platform, hwsku):
    if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]*', value):
        raise ValueError('invalid platform metadata')
platform_dir, hwsku_dir = device_info.get_paths_to_platform_and_hwsku_dirs()
expected_platform = os.path.join(expected_root, platform)
expected_hwsku = os.path.join(expected_platform, hwsku)
if os.path.realpath(platform_dir) != os.path.realpath(expected_platform) or os.path.realpath(hwsku_dir) != os.path.realpath(expected_hwsku):
    raise ValueError('installed platform/HwSKU does not match CONFIG_DB metadata')
platform_file = os.path.join(expected_platform, 'platform.json')
hwsku_file = os.path.join(expected_hwsku, 'hwsku.json')
for path in (platform_file, hwsku_file):
    if os.path.commonpath((os.path.realpath(expected_root), os.path.realpath(path))) != os.path.realpath(expected_root):
        raise ValueError('platform path escapes device root')
if os.path.realpath(device_info.get_path_to_port_config_file()) != os.path.realpath(platform_file):
    raise ValueError('native CLI would use a different platform file')
with open(platform_file) as f:
    p = json.load(f)['interfaces'][port]
with open(hwsku_file) as f:
    h = json.load(f)['interfaces'][port]
modes = {mode: get_child_ports(port, mode, platform_file) for mode in p['breakout_modes']}
# Calculate only the in-memory addition diff, never instantiate ConfigMgmt's
# DB-reading constructor or call breakOutPort/writeConfigDB. This captures the
# installed defaults actually emitted by _addPorts, not every YANG default.
cm = ConfigMgmtDPB.__new__(ConfigMgmtDPB)
cm.sysLog = lambda *args, **kwargs: None
cm.sy = SonicYang(YANG_DIR, print_log_enabled=False)
cm.sy.sysLog = lambda *args, **kwargs: None
cm.sy.loadYangModel()
native_modes = {}
for mode, ports in modes.items():
    cm.sy.loadData({'DEVICE_METADATA': {'localhost': {'hwsku': hwsku}}}, quiet=True)
    cm.configdbJsonOut = cm.sy.getData()
    cm.configdbJsonOut['PORT'] = {}
    addition, ok = cm._addPorts({'PORT': copy.deepcopy(ports)}, loadDefConfig=False)
    if not ok or set(addition) != {'PORT'} or set(addition['PORT']) != set(ports):
        raise ValueError('unsupported native addition diff')
    native_modes[mode] = {name: ConfigDBConnector.typed_to_raw(fields) for name, fields in addition['PORT'].items()}
print(json.dumps({'port': port, 'lanes': p['lanes'], 'default_mode': h['default_brkout_mode'], 'modes': modes, 'native_modes': native_modes}))
`

type breakoutPlatform struct {
	Port        string                  `json:"port"`
	Lanes       string                  `json:"lanes"`
	DefaultMode string                  `json:"default_mode"`
	Modes       map[string]vlanChangeDB `json:"modes"`
	NativeModes map[string]vlanChangeDB `json:"native_modes"`
}

var breakoutMetadataName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

func (m *SonicAgent) nativeBreakoutPlatform(ctx context.Context, port string, metadata map[string]string) (*breakoutPlatform, error) {
	if metadata["asic_name"] != "" || (metadata["switch_type"] != "" && metadata["switch_type"] != "switch") {
		return nil, fmt.Errorf("native breakout default modeling supports single-ASIC switches only")
	}
	for _, name := range []string{metadata["platform"], metadata["hwsku"]} {
		if len(name) > 128 || !breakoutMetadataName.MatchString(name) {
			return nil, fmt.Errorf("invalid platform/HwSKU metadata")
		}
	}
	if _, valid := ethernetNumber(port); !valid {
		return nil, fmt.Errorf("canonical Ethernet parent required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-c", breakoutResolverPython, port, metadata["platform"], metadata["hwsku"], "/usr/share/sonic/device")
	cmd.WaitDelay = time.Second
	out, err := m.executeBreakout(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("native platform resolver failed: %w", err)
	}
	var p breakoutPlatform
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, fmt.Errorf("invalid native platform resolver result: %w", err)
	}
	if p.Port != port {
		return nil, fmt.Errorf("resolver parent mismatch")
	}
	if len(p.NativeModes) != len(p.Modes) {
		return nil, fmt.Errorf("missing native addition model")
	}
	if err := validateBreakoutPlatform(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (m *SonicAgent) executeBreakout(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	if m.runBreakout != nil {
		return m.runBreakout(ctx, cmd)
	}
	return cmd.Output() // Do not expose CLI output, which may include configuration.
}

func (m *SonicAgent) nativeBreakout(ctx context.Context, port, mode string) error {
	ctx, cancel := context.WithTimeout(ctx, breakoutNativeTimeout)
	defer cancel()
	dir, err := os.MkdirTemp("", "sonic-breakout-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	cmd := exec.CommandContext(ctx, "config", "interface", "breakout", port, mode, "-y")
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	// nil stdin is /dev/null: a second prompt must fail, never receive another yes.
	_, err = m.executeBreakout(ctx, cmd)
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func breakoutLanes(value string) (map[string]bool, error) {
	lanes := map[string]bool{}
	for _, lane := range strings.Split(value, ",") {
		if !breakoutDecimal.MatchString(lane) || lanes[lane] {
			return nil, fmt.Errorf("invalid or duplicate lane")
		}
		lanes[lane] = true
	}
	return lanes, nil
}

var breakoutDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func validateBreakoutPlatform(p *breakoutPlatform) error {
	if p == nil {
		return fmt.Errorf("missing platform capability")
	}
	if _, valid := ethernetNumber(p.Port); !valid {
		return fmt.Errorf("invalid platform parent")
	}
	lanes, err := breakoutLanes(p.Lanes)
	if err != nil {
		return err
	}
	if len(p.Modes) == 0 || p.Modes[p.DefaultMode] == nil {
		return fmt.Errorf("missing HwSKU default mode")
	}
	for mode, children := range p.Modes {
		if len(mode) > 64 || !vlanAuthorityBreakoutMode.MatchString(mode) || len(children) == 0 {
			return fmt.Errorf("invalid platform mode")
		}
		seen := map[string]bool{}
		for name, fields := range children {
			if _, valid := ethernetNumber(name); !valid {
				return fmt.Errorf("invalid generated child name")
			}
			if !breakoutDecimal.MatchString(fields["speed"]) || fields["speed"] == "0" {
				return fmt.Errorf("invalid generated speed")
			}
			childLanes, err := breakoutLanes(fields["lanes"])
			if err != nil {
				return err
			}
			for lane := range childLanes {
				if !lanes[lane] || seen[lane] {
					return fmt.Errorf("overlapping or foreign generated lanes")
				}
				seen[lane] = true
			}
		}
		if len(seen) != len(lanes) {
			return fmt.Errorf("mode does not cover exact parent lanes")
		}
		if p.NativeModes != nil {
			native := p.NativeModes[mode]
			if len(native) != len(children) {
				return fmt.Errorf("native addition child set differs from platform")
			}
			for name, fields := range children {
				for key, value := range fields {
					if native[name][key] != value {
						return fmt.Errorf("native addition changes generated %s %s", name, key)
					}
				}
			}
		}
	}
	if p.NativeModes != nil && len(p.NativeModes) != len(p.Modes) {
		return fmt.Errorf("native addition mode set differs from platform")
	}
	return nil
}
