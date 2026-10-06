// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
)

func testReleaseBuild() ReleaseBuild {
	return ReleaseBuild{SourceCommit: strings.Repeat("a", 40), Capabilities: releaseinfo.Current().Capabilities}
}
func TestReleaseFloor(t *testing.T) {
	hash := Digest([]byte("candidate"))
	p := Policy{AgentBuilds: map[string]ReleaseBuild{hash: testReleaseBuild()}}
	if err := ValidateAgentRelease(p, hash); err != nil {
		t.Fatal(err)
	}
	if ValidateAgentRelease(p, Digest([]byte("wrong fallback"))) == nil {
		t.Fatal("unlisted fallback accepted")
	}
	for i := range testReleaseBuild().Capabilities {
		b := testReleaseBuild()
		b.Capabilities = append(b.Capabilities[:i:i], b.Capabilities[i+1:]...)
		p.AgentBuilds[hash] = b
		if ValidateAgentRelease(p, hash) == nil {
			t.Fatal("missing reader capability accepted")
		}
	}
	for _, caps := range [][]string{append(testReleaseBuild().Capabilities, "unknown-v1"), append(testReleaseBuild().Capabilities, testReleaseBuild().Capabilities[0])} {
		b := testReleaseBuild()
		b.Capabilities = caps
		p.AgentBuilds[hash] = b
		if ValidateAgentRelease(p, hash) == nil {
			t.Fatal("unknown or duplicate capability accepted")
		}
	}
}

func TestAgentRecoverySlot(t *testing.T) {
	for _, slot := range []string{"AgentBinary", "AgentUnit", "AgentCertificate", "AgentKey", "AgentCA"} {
		if !agentRecoverySlot(slot) {
			t.Fatal(slot)
		}
	}
	for _, slot := range []string{"AgentHostRecovery", "AgentHostProfile", "HostRecoveryBinary", "HostProfile", "ImportedMACHook", "PlatformJSON", "AgentFuture"} {
		if agentRecoverySlot(slot) {
			t.Fatal("host/future slot replayable", slot)
		}
	}
}

func TestReleaseRecoveryPlans(t *testing.T) {
	opts := AgentOptions{BindAddress: "192.0.2.1", Port: 50051, Artifacts: true, HostGuard: true}
	unit, _ := AgentUnit(opts)
	old, candidate := []byte("old"), []byte("candidate")
	p := Policy{AgentBuilds: map[string]ReleaseBuild{Digest(old): testReleaseBuild(), Digest(candidate): testReleaseBuild()}}
	plans := []stagedPlan{}
	inputs := map[string][]byte{"AgentBinary": candidate, "AgentUnit": unit}
	for _, f := range certificateBundle(t).Files {
		inputs[f.Slot] = f.Data
	}
	for slot, data := range inputs {
		previous := data
		if slot == "AgentBinary" {
			previous = old
		}
		_, mode, _ := Destination(slot)
		if slot == "AgentUnit" {
			mode = 0644
		}
		plans = append(plans, stagedPlan{file: File{Slot: slot, Data: data, SHA256: Digest(data)}, record: savedFile{Slot: slot, Existed: true, PreviousHash: Digest(previous), PreviousMode: mode}, previous: previous})
	}
	if err := validateAgentPlans(p, plans); err != nil {
		t.Fatal(err)
	}
	for _, slot := range []string{"AgentBinary", "AgentUnit", "AgentCertificate", "AgentKey", "AgentCA"} {
		var missing []stagedPlan
		for _, plan := range plans {
			if plan.file.Slot != slot {
				missing = append(missing, plan)
			}
		}
		if validateAgentPlans(p, missing) == nil {
			t.Fatal("incomplete recovery accepted", slot)
		}
	}
	for _, change := range []string{"binary", "guard", "endpoint", "unit", "tls", "mode"} {
		bad := append([]stagedPlan(nil), plans...)
		for i := range bad {
			if change == "mode" && bad[i].file.Slot == "AgentBinary" {
				bad[i].record.PreviousMode = 0600
			}
			if change == "tls" && bad[i].file.Slot == "AgentKey" {
				bad[i].previous = []byte("wrong old key")
			}
			if change == "binary" && bad[i].file.Slot == "AgentBinary" {
				bad[i].previous = []byte("unlisted")
			}
			if bad[i].file.Slot == "AgentUnit" {
				o := opts
				switch change {
				case "guard":
					o.HostGuard = false
				case "endpoint":
					o.BindAddress = "192.0.2.2"
				}
				if change == "guard" || change == "endpoint" {
					bad[i].previous, _ = AgentUnit(o)
				}
				if change == "unit" {
					bad[i].previous = append(append([]byte(nil), unit...), []byte("ExecStartPost=/bin/false\n")...)
				}
			}
		}
		if validateAgentPlans(p, bad) == nil {
			t.Fatal("unsafe fallback accepted", change)
		}
	}
}

func TestReleaseTLSOnlyCannotStage(t *testing.T) {
	e, _ := testEngine(t)
	b := testBundle()
	b.Agent = &AgentOptions{BindAddress: "192.0.2.1", Port: 50051, Artifacts: true, HostGuard: true}
	if _, err := e.Ensure(b, time.Now()); err == nil {
		t.Fatal("unit-only update admitted without complete accepted recovery")
	}
	j, err := e.load()
	if err != nil || j != nil {
		t.Fatal("rejected update published journal", err)
	}
}
