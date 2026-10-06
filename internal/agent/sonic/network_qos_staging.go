// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// This probe checks the installed consumer/schema contract, NOT ASIC support.
// Hardware enum/attribute capabilities are not published by qosorch 202511.
// A valid profile can be staged unbound, with RuntimeVerified remaining false.
// Fixed argv and script; no request data is executed or interpolated.
const qosSchedulerStageScript = `
import json
import re
from pathlib import Path
binary = Path('/usr/bin/orchagent').read_bytes()
schema = Path('/usr/local/yang-models/sonic-scheduler.yang').read_text()
terms = ('SCHEDULER','STRICT','WRR','DWRR','bytes','packets','type','weight','meter_type','cir','pir','cbs','pbs','scheduler')
running = False
for p in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        argv = p.read_bytes().split(bytes([0]))
        if argv[0] == b'/usr/bin/orchagent':
            running = Path(str(p.parent)+'/exe').read_bytes() == binary
            if running: break
    except FileNotFoundError:
        pass
schema_tokens = set(re.findall(r'\b(?:container|leaf|enum)\s+([A-Za-z0-9_]+)', schema))
print(json.dumps({'running': running, 'tokens': [s for s in terms if s in schema_tokens and s.encode()+bytes([0]) in binary]}))
`

// Private command seam lets Redis integration tests replace only the read-only
// host probe. Runtime name/OID proof cannot be injected through this seam.
type qosStageRunnerKey struct{}
type qosStageRunner func(*exec.Cmd) ([]byte, error)

func (r qosRedisRead) schedulerStageSupport(ctx context.Context, fields map[string]string) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", "swss", "python3", "-c", qosSchedulerStageScript)
	var data []byte
	var err error
	if run, ok := ctx.Value(qosStageRunnerKey{}).(qosStageRunner); ok {
		data, err = run(cmd)
	} else {
		data, err = cmd.Output()
	}
	if err != nil {
		return fmt.Errorf("scheduler consumer probe failed: %w", err)
	}
	return qosValidateStageSupport(data, fields)
}

func qosValidateStageSupport(data []byte, fields map[string]string) error {
	var proof struct {
		Running bool     `json:"running"`
		Tokens  []string `json:"tokens"`
	}
	if json.Unmarshal(data, &proof) != nil || !proof.Running {
		return fmt.Errorf("running scheduler consumer required for unbound staging")
	}
	tokens := map[string]bool{}
	for _, token := range proof.Tokens {
		tokens[token] = true
	}
	for _, token := range []string{"SCHEDULER", fields["type"], fields["meter_type"]} {
		if !tokens[token] {
			return fmt.Errorf("scheduler enum/table absent from installed consumer")
		}
	}
	for field := range fields {
		if !tokens[field] {
			return fmt.Errorf("scheduler attribute %s absent from installed consumer", field)
		}
	}
	return nil
}

func qosProfileUnreferenced(ctx context.Context, read qosRead, key string) error {
	table, name, _ := strings.Cut(key, "|")
	fieldName := "scheduler"
	if kind, ok := qosMapDefinition(table); ok {
		fieldName = kind.field
	}
	// Use the shared atomic, typed snapshot: CONFIG_DB_INITIALIZED is a
	// persistent string "1", not a hash. Invalid markers, expirations and all
	// other non-hash types must fail, rather than being silently skipped.
	db, err := read.configSnapshot(ctx)
	if err != nil {
		return err
	}
	for other, row := range db {
		if other == key {
			continue
		}
		for field, value := range row {
			// qosorch and tunnel consumers use raw native names. Include
			// encap_/decap_ variants, leaf lists, and qualified vendor refs.
			base := strings.TrimSuffix(field, "@")
			nameRef := base == fieldName || strings.HasSuffix(base, "_"+fieldName)
			for _, ref := range strings.Split(value, ",") {
				if ref == "["+key+"]" || ref == key || (nameRef && ref == name) {
					return fmt.Errorf("QoS profile creation/extension requires an unreferenced profile; reference in %s/%s", other, field)
				}
			}
		}
	}
	return nil
}
