// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Consumer builds qualified read-only on the tested SONiC 202511 image. A different
// consumer build requires renewed qualification, not a guessed compatibility.
var bufferConsumerBuild = map[string]string{
	"orchagent":  "fed521d9700df9b79a22696d5b50f2308e1e7cf1bfccda59b458e7f59c7d2939",
	"buffermgrd": "682a6b8bbe3b2b0ed132ba26eaad7c2b0992ef68866542336fc8083b698398bb",
}

// Hash the running executable, not merely a file replaced since daemon startup.
// Fixed argv/script; no resource values are executed or interpolated.
const bufferConsumerScript = `
import hashlib, json
from pathlib import Path
result = {}
for name in ('orchagent', 'buffermgrd'):
    matches = []
    for p in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            argv = p.read_bytes().split(bytes([0]))
            if argv and argv[0].split(b'/')[-1] == name.encode():
                matches.append(hashlib.sha256(Path(str(p.parent)+'/exe').read_bytes()).hexdigest())
        except (FileNotFoundError, ProcessLookupError):
            pass
    if len(matches) != 1:
        raise RuntimeError('expected one running ' + name)
    result[name] = matches[0]
print(json.dumps(result))
`

type bufferConsumerRunnerKey struct{}
type bufferConsumerRunner func(*exec.Cmd) ([]byte, error)

func (r qosRedisRead) bufferConsumer(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "swss", "python3", "-c", bufferConsumerScript)
	var data []byte
	var err error
	if run, ok := ctx.Value(bufferConsumerRunnerKey{}).(bufferConsumerRunner); ok {
		data, err = run(cmd)
	} else {
		data, err = cmd.Output()
	}
	if err != nil {
		return nil, fmt.Errorf("native buffer consumer read failed: %w", err)
	}
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("invalid native consumer evidence: %w", err)
	}
	return fields, nil
}

func bufferReadHash(ctx context.Context, read qosRead, db, key string) (map[string]string, error) {
	if db == "NATIVE" {
		if table, name, ok := bufferObjectKey(key); ok {
			probe, ok := read.(interface {
				bufferObject(context.Context, string, string) (map[string]string, error)
			})
			if !ok {
				return nil, fmt.Errorf("%s", bufferObjectStateUnavailable)
			}
			return probe.bufferObject(ctx, table, name)
		}
		if key != "BUFFER_CONSUMER" {
			return nil, fmt.Errorf("unsupported native buffer probe")
		}
		probe, ok := read.(interface {
			bufferConsumer(context.Context) (map[string]string, error)
		})
		if !ok {
			return nil, fmt.Errorf("native buffer consumer probe unavailable")
		}
		return probe.bufferConsumer(ctx)
	}
	return read.hash(ctx, db, key)
}
