// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func retirementFixture(t *testing.T) (*Engine, string, Bundle) {
	e, root := testEngine(t)
	b := testBundle()
	wheel, modules := syntheticWheel(t, "")
	b.Files = append(b.Files, modules...)
	b.Files = append(b.Files, File{Slot: "PlatformWheel", Data: wheel, SHA256: Digest(wheel)})
	for _, slot := range []string{"HWSKUJSON", "PortConfig", "SAIProfile", "BroadcomConfig"} {
		data := []byte("baseline")
		if slot == "SAIProfile" {
			data = []byte("SAI_INIT_CONFIG_FILE=/usr/share/sonic/hwsku/dc-flex-with-sfp.config.bcm\nSAI_NUM_ECMP_MEMBERS=64\n")
		}
		if slot == "HWSKUJSON" {
			data = []byte(`{}`)
		}
		b.Files = append(b.Files, File{Slot: slot, Data: data, SHA256: Digest(data)})
	}
	for _, f := range b.Files {
		p := ""
		if name, ok := platformModules[f.Slot]; ok {
			p = "/usr/local/lib/python3.13/dist-packages/sonic_platform/" + name
		} else {
			names := map[string]string{"PlatformJSON": "platform.json", "PlatformWheel": "sonic_platform-1.0-py3-none-any.whl", "HWSKUJSON": "hwsku.json", "PortConfig": "port_config.ini", "SAIProfile": "sai.profile", "BroadcomConfig": "dc-flex-with-sfp.config.bcm"}
			p = corePlatformDir + "/" + names[f.Slot]
		}
		e.Policy.Platform[f.Slot] = p
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0700)
		os.WriteFile(full, f.Data, 0644)
	}
	for _, p := range []string{legacyHookPath, legacyScriptPath} {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0700)
		os.WriteFile(full, []byte("original working recovery"), 0644)
	}
	b.RetireLegacyHook = true
	return e, root, b
}
func TestLegacyRetirementOccursOnlyAfterConfirmation(t *testing.T) {
	e, root, b := retirementFixture(t)
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(now)
	p := filepath.Join(root, legacyHookPath)
	got, _ := os.ReadFile(p)
	if string(got) != "original working recovery" {
		t.Fatal("working hook retired before ownership confirmation")
	}
	e.Health = func() error { return os.ErrInvalid }
	if _, err := e.Confirm(b, r.Token, now); err == nil {
		t.Fatal("unhealthy bundle retired hook")
	}
	e.Health = func() error { return nil }
	reloads := 0
	e.Finalize = func() error { reloads++; return nil }
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(p)
	if string(got) != legacyRetiredMarker || reloads != 1 {
		t.Fatal("retirement was not generated and reloaded")
	}
	observed, err := e.Observe(b)
	if err != nil || !observed.Persistence {
		t.Fatalf("retired ownership not durable: %+v %v", observed, err)
	}
}
func TestInterruptedLegacyRetirementRestoresWorkingHook(t *testing.T) {
	e, root, b := retirementFixture(t)
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(now)
	e.Finalize = func() error { return os.ErrInvalid }
	if _, err := e.Confirm(b, r.Token, now); err == nil {
		t.Fatal("failed systemd reload accepted")
	}
	e.Close()
	next, err := Open(root, "/host/artifacts", e.Policy, func() error { return nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.Finalize = func() error { return nil }
	if err := next.Tick(now); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{legacyHookPath, legacyScriptPath} {
		got, _ := os.ReadFile(filepath.Join(root, p))
		if string(got) != "original working recovery" {
			t.Fatal("interrupted retirement lost old recovery hook")
		}
	}
}
