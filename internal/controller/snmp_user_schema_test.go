//go:build integration

// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"path/filepath"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestSwitchSystemSNMPUserSchema(t *testing.T) {
	env := &envtest.Environment{ErrorIfCRDPathMissing: true, CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switchsystems.yaml")}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, users string
		valid       bool
	}{
		{"defaults-to-authpriv", `[{name: monitor, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}, privPasswordSecretRef: {namespace: system, name: snmp-users, key: priv}}]`, true},
		{"authnopriv", `[{name: monitor, securityLevel: authNoPriv, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}]`, true},
		{"authpriv-without-priv", `[{name: monitor, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}]`, false},
		{"authnopriv-with-priv", `[{name: monitor, securityLevel: authNoPriv, privProtocol: AES, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}]`, false},
		{"md5", `[{name: monitor, securityLevel: authNoPriv, authProtocol: MD5, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}]`, false},
		{"short-name", `[{name: mon, securityLevel: authNoPriv, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}]`, false},
		{"duplicate", `[{name: monitor, securityLevel: authNoPriv, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}, {name: monitor, securityLevel: authNoPriv, authPasswordSecretRef: {namespace: system, name: snmp-users, key: auth}}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{}
			doc := `{apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1, kind: SwitchSystem, metadata: {name: ` + tc.name + `}, spec: {switchRef: {name: sw}, snmp: {location: rack, users: ` + tc.users + `}}}`
			if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
				t.Fatal(err)
			}
			err := c.Create(t.Context(), obj, client.DryRunAll)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("expected invalid, got %v", err)
			}
		})
	}
}
