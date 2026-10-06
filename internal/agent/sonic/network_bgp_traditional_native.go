// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Read-only qualification of the inspected SONiC 202411 / FRR 10.0.1 startup,
// native templates/constants and bgpcfgd consumers. Different bundles need
// explicit qualification; request input cannot approve an arbitrary bundle.
const traditionalBundleDigest = "6feca683e98bdb71ddf1484eaed2160f506423b7c834f883c860ce2e2ac988d4"
const traditionalBundleScript = `import pathlib,hashlib,json,bgpcfgd
paths=[pathlib.Path(p) for p in ['/usr/bin/docker_init.sh','/etc/sonic/constants.yml','/usr/lib/frr/bgpd','/usr/lib/frr/zebra','/usr/lib/frr/staticd','/usr/local/bin/bgpcfgd','/etc/supervisor/conf.d/supervisord.conf']]
paths += [p for p in pathlib.Path('/usr/share/sonic/templates').rglob('*') if p.is_file()]
paths += [p for p in pathlib.Path(bgpcfgd.__file__).parent.rglob('*.py') if p.is_file()]
result={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}
print(hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest())`

// All rendering is stdout-only. The candidate changes only the typed ASN/type
// in an in-memory copy; framework/mode and all other inputs remain unmodified.
// setsrc uses the same template and arguments as installed ZebraSetSrc.
const traditionalRenderScript = `import subprocess,json,pathlib,sys,ipaddress
from bgpcfgd.template import TemplateFabric
source=sys.argv[1]
assert source in ['live','saved','candidate']
data=json.loads(pathlib.Path('/etc/sonic/config_db.json').read_text()) if source=='saved' else json.loads(subprocess.check_output(['sonic-cfggen','-d','--print-data']))
if source=='candidate':
    asn=int(sys.argv[2]); assert 0<asn<4294967296
    data['DEVICE_METADATA']['localhost'].update(bgp_asn=str(asn),type='LeafRouter')
templates={'bgpd.conf':'bgpd/gen_bgpd.conf.j2','zebra.conf':'zebra/zebra.conf.j2','staticd.conf':'staticd/gen_staticd.conf.j2'}
result={}
for name,template in templates.items():
    result[name]=subprocess.check_output(['sonic-cfggen','-j','/dev/stdin','-y','/etc/sonic/constants.yml','-t','/usr/share/sonic/templates/'+template],input=json.dumps(data).encode()).decode()
addresses=[k.split('|',1)[1] for k in data.get('LOOPBACK_INTERFACE',{}) if k.startswith('Loopback0|')]
assert len(addresses)==1
prefix=ipaddress.ip_interface(addresses[0]); assert prefix.version==4 and prefix.network.prefixlen==32
result['setsrc.conf']=TemplateFabric().from_file('zebra/zebra.set_src.conf.j2').render(rm_name='RM_SET_SRC',lo_ip=str(prefix.ip),ip_proto='')
print(json.dumps(result,sort_keys=True))`

func traditionalCommand(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.WaitDelay = time.Second
	var data []byte
	var err error
	if run, ok := ctx.Value(routingCommandRunnerKey{}).(routingCommandRunner); ok {
		data, err = run(cmd)
	} else {
		var out routingBoundedOutput
		cmd.Stdout = &out
		err = cmd.Run()
		data = out.buffer.Bytes()
	}
	if err != nil || ctx.Err() != nil || len(data) > 4<<20 {
		return nil, fmt.Errorf("traditional native evidence command failed")
	}
	return data, nil
}

func traditionalQualified(ctx context.Context) error {
	host, err := traditionalCommand(ctx, "python3", "-c", traditionalHostScript)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(host)) != traditionalHostDigest {
		return fmt.Errorf("unqualified traditional host activation inputs")
	}
	data, err := traditionalCommand(ctx, "docker", "exec", "bgp", "python3", "-c", traditionalBundleScript)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(data)) != traditionalBundleDigest {
		return fmt.Errorf("unqualified traditional startup/consumer bundle")
	}
	data, err = traditionalCommand(ctx, "docker", "inspect", "bgp", "--format", "{{json .Mounts}}")
	if err != nil {
		return err
	}
	var mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          *bool
		Mode        string
		Propagation string
	}
	if mlagJSON(data, &mounts, false) != nil {
		return fmt.Errorf("invalid traditional mount evidence")
	}
	frr, sonic := false, false
	for _, mount := range mounts {
		if strings.HasPrefix(mount.Destination, "/etc/frr/") || strings.HasPrefix(mount.Destination, "/etc/sonic/") {
			return fmt.Errorf("shadowed traditional startup input mount")
		}
		if mount.Destination == "/etc/frr" {
			if frr || mount.Type != "bind" || mount.Source != "/etc/sonic/frr" || mount.RW == nil || !*mount.RW {
				return fmt.Errorf("unsupported FRR startup mount")
			}
			frr = true
		}
		if mount.Destination == "/etc/sonic" {
			if sonic || mount.Type != "bind" || mount.Source != "/etc/sonic" || mount.RW == nil || *mount.RW {
				return fmt.Errorf("unsupported SONiC input mount")
			}
			sonic = true
		}
	}
	if !frr || !sonic {
		return fmt.Errorf("traditional startup input mounts missing")
	}
	return nil
}

func traditionalRender(ctx context.Context, source string, asn uint32) (map[string]string, error) {
	if source != "live" && source != "saved" && source != "candidate" {
		return nil, fmt.Errorf("invalid traditional render source")
	}
	data, err := traditionalCommand(ctx, "docker", "exec", "bgp", "python3", "-c", traditionalRenderScript, source, strconv.FormatUint(uint64(asn), 10))
	if err != nil {
		return nil, err
	}
	var files map[string]string
	if mlagJSON(data, &files, false) != nil || len(files) != 4 || files["bgpd.conf"] == "" || files["zebra.conf"] == "" || files["staticd.conf"] == "" || files["setsrc.conf"] == "" {
		return nil, fmt.Errorf("invalid traditional render evidence")
	}
	return files, nil
}

// Parse only native string fields used by the contract. Preserve other table
// identities so any foreign routing inputs still fail closed, without copying
// unrelated values or secrets into diagnostics or the ownership journal.
func traditionalSavedDB(data []byte) (vlanChangeDB, error) {
	var native map[string]map[string]map[string]json.RawMessage
	if len(data) > 4<<20 || mlagJSON(data, &native, false) != nil || native == nil {
		return nil, fmt.Errorf("invalid saved traditional source JSON")
	}
	db := vlanChangeDB{}
	for table, rows := range native {
		for name, fields := range rows {
			key := table + "|" + name
			db[key] = map[string]string{}
			if table != "DEVICE_METADATA" && table != "LOOPBACK_INTERFACE" && table != "BGP_DEVICE_GLOBAL" {
				continue
			}
			for field, raw := range fields {
				var value string
				if json.Unmarshal(raw, &value) != nil {
					return nil, fmt.Errorf("invalid saved traditional source field")
				}
				db[key][field] = value
			}
		}
	}
	return db, nil
}

func traditionalPersistence(ctx context.Context, s routingBGPSpec) (bool, error) {
	data, err := traditionalCommand(ctx, "cat", "/etc/sonic/config_db.json")
	if err != nil {
		return false, err
	}
	db, err := traditionalSavedDB(data)
	if err != nil {
		return false, err
	}
	if traditionalInputs(db, s) != nil || !networkSubset(db, traditionalDesired(s)) {
		return false, nil
	}
	if err := traditionalQualified(ctx); err != nil {
		return false, err
	}
	files, err := traditionalRender(ctx, "saved", 0)
	if err != nil {
		return false, err
	}
	matched, err := traditionalPolicy(files, s, false)
	if err != nil || !matched {
		return false, err
	}
	latest, err := traditionalCommand(ctx, "cat", "/etc/sonic/config_db.json")
	if err != nil {
		return false, err
	}
	return bytes.Equal(data, latest), nil
}

func traditionalRuntime(ctx context.Context, m *SonicAgent, s routingBGPSpec) (bool, json.RawMessage, error) {
	if err := traditionalQualified(ctx); err != nil {
		return false, nil, err
	}
	// bgpcfgd also consumes these non-CONFIG_DB inputs after startup. Pending
	// foreign policy must not be mistaken for a reproducible peerless baseline.
	for _, input := range []struct{ db, pattern string }{
		{"APPL_DB", "STATIC_ROUTE:*"}, {"APPL_DB", "BGP_PROFILE_TABLE:*"}, {"STATE_DB", "ADVERTISE_NETWORK_TABLE|*"},
	} {
		keys, err := (qosRedisRead{agent: m}).keys(ctx, input.db, input.pattern)
		if err != nil {
			return false, nil, err
		}
		if len(keys) != 0 {
			return false, nil, fmt.Errorf("foreign dynamic routing input blocks traditional BGP regeneration")
		}
	}
	daemons, err := runRoutingRead(ctx, routingBGPDaemons)
	if err != nil {
		return false, nil, err
	}
	config, err := runRoutingRead(ctx, routingBGPConfig)
	if err != nil {
		return false, nil, err
	}
	matched, err := traditionalPolicy(map[string]string{"running": string(config)}, s, true)
	if err != nil {
		return false, nil, err
	}
	summary, err := runRoutingRead(ctx, routingBGPSummary)
	if err != nil {
		return false, nil, err
	}
	var peers map[string]map[string]json.RawMessage
	if mlagJSON(summary, &peers, false) != nil || len(peers) != 1 || peers["default"] == nil || len(peers["default"]) != 0 {
		return false, nil, fmt.Errorf("traditional backend requires exact empty default-VRF neighbor summary")
	}
	stateReady, err := traditionalLoopbackState(ctx, m, s)
	if err != nil {
		return false, nil, err
	}
	consumer := frrMigrationDaemonReady(daemons, false)
	ready := matched && consumer && stateReady
	observed, _ := json.Marshal(map[string]any{"mode": "Traditional", "consumer": "bgpcfgd", "consumerRunning": consumer, "runningConfigMatches": matched, "loopbackStateReady": stateReady, "neighborsEmpty": true, "forwardingTested": false})
	return ready, observed, nil
}
