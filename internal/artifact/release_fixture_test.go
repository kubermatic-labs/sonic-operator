// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

// Existing lifecycle fixtures now seed the same complete recovery contract that
// production requires. ELF bytes are synthetic; native execution is injected.
func completeAgentFixture(t *testing.T, e *Engine, b *Bundle) {
	t.Helper()
	if b.Agent == nil {
		b.Agent = &AgentOptions{BindAddress: "192.0.2.1", Port: 50051, Artifacts: true, HostGuard: true}
	}
	existing := map[string]bool{}
	for _, f := range b.Files {
		existing[f.Slot] = true
	}
	tls := certificateBundle(t)
	seed, _ := bootstrapFixture(t)
	for _, f := range append(tls.Files, File{Slot: "AgentBinary", Data: seed.Bootstrap.Supervisor, SHA256: seed.Bootstrap.SupervisorSHA256}) {
		if !existing[f.Slot] {
			b.Files = append(b.Files, f)
		}
	}
	unit, _ := AgentUnit(*b.Agent)
	if e.Policy.AgentBuilds == nil {
		e.Policy.AgentBuilds = map[string]ReleaseBuild{}
	}
	for _, f := range append(append([]File(nil), b.Files...), File{Slot: "AgentUnit", Data: unit}) {
		if !agentRecoverySlot(f.Slot) {
			continue
		}
		p, m, err := e.destination(f.Slot)
		if f.Slot == "AgentUnit" {
			p = "etc/systemd/system/sonic-operator-agent.service"
			m = 0644
			err = nil
		}
		if err != nil {
			t.Fatal(err)
		}
		full := filepath.Join(e.root.Name(), p)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		old, err := os.ReadFile(full)
		if os.IsNotExist(err) {
			if err = os.WriteFile(full, f.Data, m); err != nil {
				t.Fatal(err)
			}
			old = f.Data
		} else if err != nil {
			t.Fatal(err)
		}
		if f.Slot == "AgentBinary" {
			e.Policy.AgentBuilds[Digest(f.Data)] = testReleaseBuild()
			e.Policy.AgentBuilds[Digest(old)] = testReleaseBuild()
		}
	}
}
