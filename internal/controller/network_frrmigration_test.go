// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestNetworkFRRMigrationApproval(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"Unified", "Traditional"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			testNetworkFRRMigrationApproval(t, mode)
		})
	}
}

func testNetworkFRRMigrationApproval(t *testing.T, mode string) {
	t.Helper()
	for _, scenario := range []string{"approved", "missing", "mismatch", "ineligible", "missing preflight", "malformed preflight", "missing digest", "wrong mode", "missing mode", "stale status", "gate disabled", "network gate disabled", "global observe", "observe", "drift after binding"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			obj, _, a, c, r := networkFixture(t, "FRRMigration", networkTestSpecs[7].spec)
			migration := obj.(*api.SwitchFRRMigration)
			migration.Spec.Mode = mode
			if err := c.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			observed := map[string]any{"preflightEligible": true, "adoptionDigest": strings.Repeat("a", 64), "mode": mode}
			a.current.Observed, _ = json.Marshal(observed)
			wantErr := true
			switch scenario {
			case "approved":
				wantErr = false
			case "missing":
				migration.Spec.ApprovedDigest = ""
			case "mismatch":
				migration.Spec.ApprovedDigest = strings.Repeat("b", 64)
			case "ineligible":
				observed["preflightEligible"] = false
			case "missing preflight":
				delete(observed, "preflightEligible")
			case "malformed preflight":
				observed["preflightEligible"] = "true"
			case "missing digest":
				delete(observed, "adoptionDigest")
			case "wrong mode":
				observed["mode"] = "split"
			case "missing mode":
				delete(observed, "mode")
			case "stale status":
				migration.Status.Observed.Raw = append([]byte(nil), a.current.Observed...)
				if err := c.Status().Update(t.Context(), migration); err != nil {
					t.Fatal(err)
				}
				observed["adoptionDigest"] = strings.Repeat("b", 64)
			case "gate disabled":
				r.AllowFRRMigration = false
				wantErr = false
			case "network gate disabled":
				r.AllowNetworkConfig = false
				wantErr = false
			case "global observe":
				r.ObserveOnly = true
				wantErr = false
			case "observe":
				migration.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
				migration.Spec.ApprovedDigest = ""
				wantErr = false
			case "drift after binding":
				if _, err := r.Reconcile(t.Context(), request); err != nil {
					t.Fatal(err)
				}
				if err := c.Get(t.Context(), request.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				observed["adoptionDigest"] = strings.Repeat("b", 64)
			}
			if err := c.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			a.current.Observed, _ = json.Marshal(observed)
			preview := string(a.current.Observed)
			for i := 0; i < 2; i++ {
				_, err := r.Reconcile(t.Context(), request)
				if (err != nil) != wantErr {
					t.Fatalf("reconcile %d: err=%v wantErr=%v", i, err, wantErr)
				}
			}
			wantWrites := 0
			if scenario == "approved" {
				wantWrites = 1
			}
			if len(a.requests) != wantWrites {
				t.Fatalf("Ensure count=%d want=%d", len(a.requests), wantWrites)
			}
			if err := c.Get(t.Context(), request.NamespacedName, obj); err != nil {
				t.Fatal(err)
			}
			if wantWrites == 0 {
				if string(migration.Status.Observed.Raw) != preview {
					t.Fatalf("preflight result not published: %s", migration.Status.Observed.Raw)
				}
				if meta.IsStatusConditionTrue(migration.Status.Conditions, "Ready") {
					t.Fatal("preflight eligibility implied migration readiness")
				}
			}
		})
	}
}

func TestNetworkFRRMigrationRecoveryOriginalApproval(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"expired", "removed", "invalid new digest", "gate disabled", "mode changed", "pending restart", "pending save", "delete expired"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			obj, _, a, c, r := networkFixture(t, "FRRMigration", networkTestSpecs[7].spec)
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			if _, err := r.Reconcile(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			a.writeErr = errors.New("activation or save pending")
			if _, err := r.Reconcile(t.Context(), request); err == nil || len(a.requests) != 1 {
				t.Fatalf("expected journaled uncertain Ensure: %v", err)
			}
			original := a.requests[0]
			if err := c.Get(t.Context(), request.NamespacedName, obj); err != nil {
				t.Fatal(err)
			}
			migration := obj.(*api.SwitchFRRMigration)
			switch scenario {
			case "removed":
				migration.Spec.ApprovedDigest = ""
			case "invalid new digest":
				migration.Spec.ApprovedDigest = "invalid"
			case "gate disabled":
				r.AllowFRRMigration = false
			case "mode changed":
				migration.Spec.Mode = "split"
			case "pending restart", "pending save":
				a.recoverErr = errors.New(scenario)
			}
			if err := c.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			// Metadata has already changed, so the old preflight is no longer eligible.
			a.current.Observed = json.RawMessage(`{"preflightEligible":false,"mode":"Unified"}`)
			a.recoveries = nil
			if scenario == "delete expired" {
				if err := c.Delete(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
			}
			_, err := r.Reconcile(t.Context(), request)
			if scenario == "delete expired" {
				if err != nil {
					t.Fatalf("expired approval blocked original journal recovery: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("new Ensure must not use expired or invalid approval")
				}
				if err := c.Get(t.Context(), request.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(obj.GetFinalizers(), networkRecoveryFinalizer) || obj.GetAnnotations()[networkRequestAnnotation] != string(original.Spec) {
					t.Fatal("original recovery binding lost")
				}
			}
			wantRecover := scenario != "gate disabled"
			if (len(a.recoveries) == 1) != wantRecover {
				t.Fatalf("recovery calls=%d want=%v", len(a.recoveries), wantRecover)
			}
			if wantRecover && !reflect.DeepEqual(a.recoveries[0], original) {
				t.Fatal("recovery replaced original approved request")
			}
			if len(a.requests) != 1 {
				t.Fatal("expired approval triggered another Ensure")
			}
		})
	}
}

func TestNetworkFRRMigrationModeEdit(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"Unified", "Traditional"} {
		for _, pending := range []string{"restart", "save", "confirmed"} {
			t.Run(mode+"/"+pending, func(t *testing.T) {
				t.Parallel()
				obj, sw, a, c, r := networkFixture(t, "FRRMigration", networkTestSpecs[7].spec)
				migration := obj.(*api.SwitchFRRMigration)
				migration.Spec.Mode = mode
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				preview := func(target, digest string) {
					raw, err := json.Marshal(map[string]any{"mode": target, "preflightEligible": true, "adoptionDigest": digest})
					if err != nil {
						t.Fatal(err)
					}
					a.current = &agent.NetworkResult{Observed: raw}
				}
				preview(mode, migration.Spec.ApprovedDigest)
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
				if _, err := r.Reconcile(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if pending != "confirmed" {
					a.writeErr = errors.New("lost " + pending + " response")
				}
				_, err := r.Reconcile(t.Context(), req)
				if (err != nil) != (pending != "confirmed") || len(a.requests) != 1 {
					t.Fatalf("original Ensure: err=%v requests=%d", err, len(a.requests))
				}
				original := a.requests[0]
				if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				binding := obj.GetAnnotations()[networkTargetAnnotation]
				if binding != networkBinding(obj, sw, "FRRMigration", "unified") {
					t.Fatal("migration lost the legacy device-wide binding")
				}
				migration.Spec.Mode = "Traditional"
				if mode == "Traditional" {
					migration.Spec.Mode = "Unified"
				}
				migration.Generation++
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				a.recoveries = nil
				a.recoverErr = errors.New("original operation still pending")
				reads := 0
				a.onRead = func() { reads++ }
				if _, err := r.Reconcile(t.Context(), req); err == nil {
					t.Fatal("new mode bypassed pending recovery")
				}
				if len(a.recoveries) != 1 || !reflect.DeepEqual(a.recoveries[0], original) || reads != 0 {
					t.Fatal("recovery must receive the original mode and approval before any new preview")
				}
				a.recoverErr, a.writeErr = nil, nil
				// A completed original operation is not evidence for the new target.
				a.recovery = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true}
				freshDigest := strings.Repeat("b", 64)
				preview(migration.Spec.Mode, freshDigest)
				if _, err := r.Reconcile(t.Context(), req); err == nil || !strings.Contains(err.Error(), "approvedDigest") {
					t.Fatalf("old approval authorized the new target: %v", err)
				}
				if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				if len(a.requests) != 1 || obj.GetAnnotations()[networkRequestAnnotation] != string(original.Spec) || obj.GetAnnotations()[networkTargetAnnotation] != binding || !slices.Contains(obj.GetFinalizers(), networkRecoveryFinalizer) {
					t.Fatal("unapproved mode edit changed the recorded request, binding or device")
				}
				if meta.IsStatusConditionTrue(migration.Status.Conditions, "Ready") {
					t.Fatal("original completion marked the new target Ready")
				}
				migration.Spec.ApprovedDigest = freshDigest
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				preview(mode, freshDigest)
				if _, err := r.Reconcile(t.Context(), req); err == nil {
					t.Fatal("wrong-direction preview authorized Ensure")
				}
				preview(migration.Spec.Mode, freshDigest)
				if _, err := r.Reconcile(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if len(a.requests) != 1 {
					t.Fatal("new request was dispatched before being recorded")
				}
				for _, recovered := range a.recoveries {
					if !reflect.DeepEqual(recovered, original) {
						t.Fatal("new spec replaced original recovery request prematurely")
					}
				}
				for i := 0; i < 3; i++ {
					if _, err := r.Reconcile(t.Context(), req); err != nil {
						t.Fatal(err)
					}
				}
				if len(a.requests) != 2 {
					t.Fatalf("expected one Ensure per transition, got %d", len(a.requests))
				}
				var next api.SwitchFRRMigrationSpec
				if err := json.Unmarshal(a.requests[1].Spec, &next); err != nil {
					t.Fatal(err)
				}
				if next.Mode != migration.Spec.Mode || next.ApprovedDigest != freshDigest || a.requests[1].OwnerID != original.OwnerID {
					t.Fatalf("new transition changed owner or replayed original intent: %+v", a.requests[1])
				}
				if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				if obj.GetAnnotations()[networkTargetAnnotation] != binding || obj.GetAnnotations()[networkRequestAnnotation] != string(a.requests[1].Spec) {
					t.Fatal("mode edit replaced the binding or failed to retain the new recovery request")
				}
			})
		}
	}
}

func TestNetworkFRRMigrationOppositeClaims(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"Unified", "Traditional"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			obj, _, a, c, r := networkFixture(t, "FRRMigration", networkTestSpecs[7].spec)
			migration := obj.(*api.SwitchFRRMigration)
			migration.Spec.Mode = mode
			if err := c.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			other := migration.DeepCopy()
			other.Name, other.UID, other.ResourceVersion = "opposite", "other-uid", ""
			other.Spec.Mode = "Traditional"
			if mode == "Traditional" {
				other.Spec.Mode = "Unified"
			}
			if err := c.Create(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil || !strings.Contains(err.Error(), `also claims target "unified"`) {
				t.Fatalf("opposite-direction claim not rejected as the same target: %v", err)
			}
			if len(a.requests) != 0 {
				t.Fatal("conflicting claim caused a write")
			}
		})
	}
}

func TestNetworkFRRMigrationPersistenceRefresh(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"Unified", "Traditional"} {
		for _, scenario := range []string{"completed", "approval removed", "initial claim", "missing binding", "wrong binding", "missing finalizer", "missing request", "wrong recorded mode", "wrong observed mode", "pending", "missing classification", "configuration unverified", "runtime unverified", "absent", "read error", "migration gate disabled", "network gate disabled", "global observe", "observe"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				t.Parallel()
				obj, _, a, c, r := networkFixture(t, "FRRMigration", networkTestSpecs[7].spec)
				migration := obj.(*api.SwitchFRRMigration)
				migration.Spec.Mode = mode
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				preview, _ := json.Marshal(map[string]any{"mode": mode, "preflightEligible": true, "adoptionDigest": migration.Spec.ApprovedDigest})
				a.current.Observed = preview
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
				for i := 0; i < 2; i++ {
					if _, err := r.Reconcile(t.Context(), req); err != nil {
						t.Fatal(err)
					}
				}
				if len(a.requests) != 1 {
					t.Fatal("expected completed initial migration")
				}
				original := a.requests[0]
				if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				binding := obj.GetAnnotations()[networkTargetAnnotation]
				// Model a changed full-DB persistence fingerprint after an unrelated
				// VLAN save. Routing may now be populated: no empty-routing preflight
				// or new adoption digest is available for this completed migration.
				observed := map[string]any{"mode": mode, "classification": "migration-complete", "preflightEligible": false, "adoptionDigest": ""}
				a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, RuntimeVerified: true}
				wantRefresh := scenario == "completed" || scenario == "approval removed"
				switch scenario {
				case "approval removed":
					migration.Spec.ApprovedDigest = ""
				case "initial claim":
					obj.SetAnnotations(nil)
					obj.SetFinalizers(nil)
				case "missing binding":
					delete(obj.GetAnnotations(), networkTargetAnnotation)
				case "wrong binding":
					obj.GetAnnotations()[networkTargetAnnotation] = "foreign-uid-binding"
				case "missing finalizer":
					obj.SetFinalizers(nil)
				case "missing request":
					delete(obj.GetAnnotations(), networkRequestAnnotation)
				case "wrong recorded mode":
					var saved api.SwitchFRRMigrationSpec
					if err := json.Unmarshal(original.Spec, &saved); err != nil {
						t.Fatal(err)
					}
					saved.Mode = "Traditional"
					if mode == "Traditional" {
						saved.Mode = "Unified"
					}
					raw, _ := json.Marshal(saved)
					obj.GetAnnotations()[networkRequestAnnotation] = string(raw)
				case "wrong observed mode":
					observed["mode"] = "Traditional"
					if mode == "Traditional" {
						observed["mode"] = "Unified"
					}
				case "pending":
					observed["classification"] = "migration-pending"
				case "missing classification":
					delete(observed, "classification")
				case "configuration unverified":
					a.current.ConfigurationVerified = false
				case "runtime unverified":
					a.current.RuntimeVerified = false
				case "absent":
					a.current.Exists = false
				case "read error":
					a.readErr = errors.New("foreign owner")
				case "migration gate disabled":
					r.AllowFRRMigration = false
				case "network gate disabled":
					r.AllowNetworkConfig = false
				case "global observe":
					r.ObserveOnly = true
				case "observe":
					migration.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
				}
				a.current.Observed, _ = json.Marshal(observed)
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				a.recoveries = nil
				for i := 0; i < 3; i++ {
					_, err := r.Reconcile(t.Context(), req)
					if wantRefresh && err != nil {
						t.Fatalf("same-mode persistence refresh blocked: %v", err)
					}
				}
				wantWrites := 1
				if wantRefresh {
					wantWrites++
				}
				if len(a.requests) != wantWrites {
					t.Fatalf("Ensure count=%d want=%d", len(a.requests), wantWrites)
				}
				if wantRefresh {
					if len(a.recoveries) == 0 || !reflect.DeepEqual(a.recoveries[0], original) {
						t.Fatal("refresh bypassed original request recovery")
					}
					var refreshed api.SwitchFRRMigrationSpec
					if err := json.Unmarshal(a.requests[1].Spec, &refreshed); err != nil {
						t.Fatal(err)
					}
					if refreshed.Mode != mode || a.requests[1].OwnerID != original.OwnerID {
						t.Fatal("refresh changed target mode or owner")
					}
					if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
						t.Fatal(err)
					}
					if obj.GetAnnotations()[networkTargetAnnotation] != binding || !meta.IsStatusConditionTrue(migration.Status.Conditions, "Ready") {
						t.Fatal("refresh lost binding or did not restore readiness")
					}
				}
			})
		}
	}
}
