//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// The production assembly calls this interface. Only native IO and privileged
// creation of already-existing fixture journals are substituted; host-journal
// configuration is the real SonicAgent method and starts empty.
type watchdogAssemblyFixture struct {
	*SonicAgent
	native *host.Native
}

func (f watchdogAssemblyFixture) NewHostNative() *host.Native { return f.native }
func (f watchdogAssemblyFixture) attach(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err = vlanAuthoritySecure(info, true); err != nil {
		return err
	}
	lock, err := os.Lstat(filepath.Join(path, ".lock"))
	if err != nil {
		return err
	}
	return vlanAuthoritySecure(lock, false)
}
func (f watchdogAssemblyFixture) ConfigureNetworkJournal(path string) error {
	if err := f.attach(path); err != nil {
		return err
	}
	f.networkJournalDir = path
	return nil
}
func (f watchdogAssemblyFixture) ConfigureVLANAuthorityJournal(path string) error {
	if err := f.attach(path); err != nil {
		return err
	}
	f.journalDir = path
	return nil
}
func (f watchdogAssemblyFixture) ConfigureBreakoutJournal(path string) error {
	if err := f.attach(path); err != nil {
		return err
	}
	f.breakoutJournalDir = path
	return nil
}

func TestStandaloneWatchdogAssemblyRecoversConfiguredLegacyDependency(t *testing.T) {
	for _, dependency := range []string{"network", "vlan"} {
		t.Run(dependency, func(t *testing.T) {
			f, rdb, req := hostNetworkFixture(t)
			if dependency == "vlan" {
				dir := filepath.Join(f.dir, "vlan")
				_ = os.Mkdir(dir, 0700)
				_ = os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600)
				f.agent.journalDir = dir
				f.agent.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error { return nil }
			}
			save := f.agent.saveConfig
			f.agent.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			if dependency == "network" {
				if _, st := f.agent.EnsureNetworkResource(t.Context(), req); st == nil {
					t.Fatal("missing network pending state")
				}
			} else {
				snapshot, st := f.agent.GetVLANAuthority(t.Context(), 100)
				if st != nil {
					t.Fatal(st.Message)
				}
				if _, st = f.agent.ReconcileVLANAuthority(t.Context(), &agent.VLANAuthorityRequest{OwnerID: "vlan-owner", VLAN: &agent.VLAN{ID: 100}, AdoptionDigest: snapshot.Digest}); st == nil {
					t.Fatal("missing VLAN pending state")
				}
			}
			f.agent.saveConfig = save
			k := f.kernel()
			delete(k.Routes, hostRoute("10.0.0.0/24", ""))
			f.putKernel(k)
			seedLegacyHostPending(t, f)
			cfg := host.RecoveryConfig{JournalDir: filepath.Join(f.dir, "journal"), RedisAddress: rdb.Options().Addr, VLANJournalDir: f.agent.journalDir, NetworkJournalDir: f.agent.networkJournalDir}
			f.agent.hostJournalDir = ""
			f.agent.networkJournalDir = ""
			f.agent.journalDir = ""
			f.agent.breakoutJournalDir = ""
			engine, err := host.NewRecoveryEngine(cfg, watchdogAssemblyFixture{SonicAgent: f.agent, native: f.native})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if err = engine.RecoverExpired(ctx); err != nil {
				t.Fatal("standalone assembly skipped configured dependency recovery", err)
			}
			if f.agent.hostJournalDir != cfg.JournalDir || f.agent.networkJournalDir != cfg.NetworkJournalDir || f.agent.journalDir != cfg.VLANJournalDir {
				t.Fatal("assembly did not bind exactly the supplied RecoveryConfig")
			}
			if err = host.CheckPending(cfg.JournalDir); err != nil {
				t.Fatal(err)
			}
			if !f.kernel().Routes[hostRoute("10.0.0.0/24", "")] {
				t.Fatal("standalone watchdog did not restore management runtime")
			}
		})
	}
}
