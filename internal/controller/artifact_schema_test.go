//go:build integration

// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"path/filepath"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestArtifactSchema(t *testing.T) {
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), ErrorIfCRDPathMissing: true, CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switchartifacts.yaml")}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	api.AddToScheme(scheme)
	corev1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "artifact-schema"}}); err != nil {
		t.Fatal(err)
	}
	obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "artifact-schema"}, Spec: api.SwitchArtifactSpec{SwitchName: "switch", Baseline: "baseline", Files: []api.ArtifactFile{{Slot: "PlatformJSON", SHA256: strings.Repeat("a", 64), Chunks: []api.ArtifactContentRef{{Kind: "ConfigMap", Name: "revision", UID: "uid", Key: "file"}}}}}}
	if err := c.Create(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	if obj.Spec.ManagementPolicy != "Observe" || obj.Spec.Activation != "AgentRestart" {
		t.Fatal("unsafe defaults")
	}
	manage := obj.DeepCopy()
	manage.Spec.ManagementPolicy = "Manage"
	if err := c.Update(t.Context(), manage); !apierrors.IsInvalid(err) {
		t.Fatalf("Manage without owned bootstrap accepted: %v", err)
	}
	ref := obj.Spec.Files[0].Chunks[0]
	bad := obj.DeepCopy()
	bad.Name = "bad-bootstrap"
	bad.ResourceVersion = ""
	bad.UID = ""
	bad.Spec.Bootstrap = &api.ArtifactBootstrapSpec{SupervisorSHA256: strings.Repeat("a", 64), SupervisorChunks: []api.ArtifactContentRef{ref}, PolicySHA256: strings.Repeat("b", 64), PolicyRef: ref, UnitSHA256: strings.Repeat("c", 64)}
	bad.Spec.Bootstrap.PolicyRef.Kind = "Secret"
	if err := c.Create(t.Context(), bad); !apierrors.IsInvalid(err) {
		t.Fatalf("Secret-backed bootstrap accepted: %v", err)
	}
	changed := obj.DeepCopy()
	changed.Spec.SwitchName = "other-switch"
	if err := c.Update(t.Context(), changed); !apierrors.IsInvalid(err) {
		t.Fatalf("mutable target: %v", err)
	}
	for _, slot := range []string{"../../etc/passwd", "AgentKey"} {
		candidate := obj.DeepCopy()
		candidate.Spec.Files[0].Slot = slot
		if err := c.Update(t.Context(), candidate); !apierrors.IsInvalid(err) {
			t.Fatalf("invalid destination or public secret accepted (%s): %v", slot, err)
		}
	}
	yes := true
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "host-source", Namespace: "artifact-schema"}, Immutable: &yes, Data: map[string]string{"content": "schema fixture"}}
	if err := c.Create(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	hostRef := api.ArtifactContentRef{Kind: "ConfigMap", Name: source.Name, UID: string(source.UID), Key: "content"}
	hostSpec := &api.ArtifactHostRecoverySpec{BinarySHA256: strings.Repeat("a", 64), BinaryChunks: []api.ArtifactContentRef{hostRef}, ProfileSHA256: strings.Repeat("b", 64), ProfileRef: hostRef, ServiceSHA256: strings.Repeat("c", 64), TimerSHA256: strings.Repeat("d", 64), ConfigSHA256: strings.Repeat("e", 64), JournalLayout: "FleetHostV1"}
	valid := obj.DeepCopy()
	valid.Name = "host-valid"
	valid.ResourceVersion = ""
	valid.UID = ""
	valid.Spec.Agent = &api.ArtifactAgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostConfig: true, HostGuard: true}
	valid.Spec.Bootstrap = &api.ArtifactBootstrapSpec{SupervisorSHA256: strings.Repeat("a", 64), SupervisorChunks: []api.ArtifactContentRef{hostRef}, PolicySHA256: strings.Repeat("b", 64), PolicyRef: hostRef, UnitSHA256: strings.Repeat("c", 64), HostRecovery: hostSpec}
	if err := c.Create(t.Context(), valid); err != nil {
		t.Fatal("finite host baseline rejected", err)
	}
	for _, scenario := range []string{"layout", "secret", "hash", "duplicate-hook", "guard", "missing-suite"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := valid.DeepCopy()
			candidate.Name = "host-" + scenario
			candidate.ResourceVersion = ""
			candidate.UID = ""
			switch scenario {
			case "layout":
				candidate.Spec.Bootstrap.HostRecovery.JournalLayout = "/tmp/foreign"
			case "secret":
				candidate.Spec.Bootstrap.HostRecovery.ProfileRef.Kind = "Secret"
			case "hash":
				candidate.Spec.Bootstrap.HostRecovery.BinarySHA256 = strings.Repeat("A", 64)
			case "guard":
				candidate.Spec.Agent.HostGuard = false
			case "missing-suite":
				candidate.Spec.Bootstrap.HostRecovery = nil
			case "duplicate-hook":
				h := api.ArtifactMACHookSpec{Kind: "management-mac-shell", SourceHookSHA256: strings.Repeat("a", 64), HelperSHA256: strings.Repeat("b", 64), SourceHookRef: hostRef, HelperRef: hostRef}
				candidate.Spec.Bootstrap.HostRecovery.MACHooks = []api.ArtifactMACHookSpec{h, h}
			}
			if err := c.Create(t.Context(), candidate); !apierrors.IsInvalid(err) {
				t.Fatalf("invalid host declaration accepted: %v", err)
			}
		})
	}
	changedHost := valid.DeepCopy()
	changedHost.Spec.Bootstrap.HostRecovery.ProfileSHA256 = strings.Repeat("f", 64)
	if err := c.Update(t.Context(), changedHost); !apierrors.IsInvalid(err) {
		t.Fatalf("host immutable baseline changed: %v", err)
	}
	testBootstrapMigration(t, c, valid)
}

func testBootstrapMigration(t *testing.T, c client.Client, valid *api.SwitchArtifact) {
	t.Helper()
	oldPolicy := valid.Spec.Bootstrap.PolicySHA256
	migrate := func(change func(*api.SwitchArtifact)) *api.SwitchArtifact {
		candidate := valid.DeepCopy()
		candidate.Spec.Bootstrap.SupervisorSHA256 = strings.Repeat("1", 64)
		candidate.Spec.Bootstrap.PolicySHA256 = strings.Repeat("2", 64)
		candidate.Spec.BootstrapMigrationFrom = oldPolicy
		change(candidate)
		return candidate
	}
	for name, change := range map[string]func(*api.SwitchArtifact){
		"without approval":     func(a *api.SwitchArtifact) { a.Spec.BootstrapMigrationFrom = "" },
		"wrong policy":         func(a *api.SwitchArtifact) { a.Spec.BootstrapMigrationFrom = strings.Repeat("9", 64) },
		"changed unit":         func(a *api.SwitchArtifact) { a.Spec.Bootstrap.UnitSHA256 = strings.Repeat("3", 64) },
		"changed host":         func(a *api.SwitchArtifact) { a.Spec.Bootstrap.HostRecovery.ProfileSHA256 = strings.Repeat("f", 64) },
		"removed host":         func(a *api.SwitchArtifact) { a.Spec.Bootstrap.HostRecovery = nil; a.Spec.Agent.HostConfig = false },
		"removed bootstrap":    func(a *api.SwitchArtifact) { a.Spec.Bootstrap = nil; a.Spec.Agent.HostConfig = false },
		"invalid approval sha": func(a *api.SwitchArtifact) { a.Spec.BootstrapMigrationFrom = "not-a-hash" },
	} {
		if err := c.Update(t.Context(), migrate(change)); !apierrors.IsInvalid(err) {
			t.Fatalf("bootstrap migration %s accepted: %v", name, err)
		}
	}
	migrated := migrate(func(*api.SwitchArtifact) {})
	if err := c.Update(t.Context(), migrated); err != nil {
		t.Fatal("approved bootstrap migration rejected", err)
	}
	// A stale approval cannot authorize a second replacement.
	again := migrated.DeepCopy()
	again.Spec.Bootstrap.PolicySHA256 = strings.Repeat("4", 64)
	if err := c.Update(t.Context(), again); !apierrors.IsInvalid(err) {
		t.Fatalf("stale migration approval accepted: %v", err)
	}
	// Unrelated updates stay possible while the approval field remains set.
	unrelated := migrated.DeepCopy()
	unrelated.Spec.Activation = "PlatformNextBoot"
	if err := c.Update(t.Context(), unrelated); err != nil {
		t.Fatal("unrelated update rejected after migration", err)
	}
}
