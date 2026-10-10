// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	switchutil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

type artifactRPC interface {
	Artifact(context.Context, artifact.Request) (*artifact.Result, error)
}
type ArtifactReconciler struct {
	client.Client
	APIReader      client.Reader
	ObserveOnly    bool
	AllowArtifacts bool
	NewClient      func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error)
	// MaxConcurrentReconciles bounds parallel switches. A single worker serializes
	// every switch, so with several switches staging at once a confirmation can
	// miss the switch-local five-minute deadline. controller-runtime never
	// reconciles the same object concurrently.
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchartifacts,verbs=get;list;watch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchartifacts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps;secrets,verbs=get

func (r *ArtifactReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&api.SwitchArtifact{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: max(r.MaxConcurrentReconciles, 1)}).
		Complete(r)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *ArtifactReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	if r.APIReader == nil {
		return result, fmt.Errorf("artifacts require uncached API reader")
	}
	obj := &api.SwitchArtifact{}
	if err := r.APIReader.Get(ctx, req.NamespacedName, obj); err != nil {
		return result, client.IgnoreNotFound(err)
	}
	// Orphan deletion: an unconfirmed update is still reverted by the supervisor;
	// confirmed files and durable owner binding remain after resource deletion.
	if !obj.DeletionTimestamp.IsZero() {
		return result, nil
	}
	original := obj.DeepCopy()
	obj.Status.ObservedGeneration = obj.Generation
	obj.Status.ConfigurationVerified = false
	obj.Status.RuntimeVerified = false
	obj.Status.PersistenceVerified = false
	obj.Status.RecoveryPhase = "Unknown"
	obj.Status.RecoveryReason = ""
	result.RequeueAfter = 15 * time.Second
	defer func() {
		ready := retErr == nil && obj.Spec.ManagementPolicy == "Manage" && obj.Status.ConfigurationVerified && obj.Status.RuntimeVerified && obj.Status.PersistenceVerified && obj.Status.RecoveryPhase == "Confirmed"
		for _, c := range []struct {
			name string
			ok   bool
		}{{"Ready", ready}, {"ConfigurationReady", obj.Status.ConfigurationVerified}, {"RuntimeReady", obj.Status.RuntimeVerified}, {"PersistenceReady", obj.Status.PersistenceVerified}, {"RecoveryReady", obj.Status.RecoveryPhase == "Confirmed"}} {
			state := metav1.ConditionFalse
			if c.ok {
				state = metav1.ConditionTrue
			}
			reason, message := "Reconciling", "Declared artifact lifecycle verification"
			if retErr != nil {
				reason, message = "Blocked", artifactBlockedMessage(retErr)
			} else if c.ok {
				reason = "Verified"
			}
			meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: c.name, Status: state, Reason: reason, Message: message, ObservedGeneration: obj.Generation})
		}
		retErr = errors.Join(retErr, r.Status().Patch(ctx, obj, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})))
	}()
	sw := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: obj.Spec.SwitchName}, sw); err != nil {
		return result, fmt.Errorf("artifact Switch unavailable")
	}
	port, err := strconv.Atoi(sw.Spec.Management.Port)
	if err != nil || port < 1 || port > 65535 || sw.UID == "" || sw.Spec.Management.Host == "" || !sw.DeletionTimestamp.IsZero() || obj.UID == "" {
		return result, fmt.Errorf("artifact target identity and endpoint required")
	}
	targetBytes, _ := json.Marshal(struct {
		UID        string
		Management api.Management
	}{string(sw.UID), sw.Spec.Management})
	target := artifact.Digest(targetBytes)
	if obj.Status.Target != "" && obj.Status.Target != target {
		return result, fmt.Errorf("artifact target identity or endpoint changed")
	}
	if obj.Status.Target == "" {
		obj.Status.Target = target
		return result, nil
	} // durable binding precedes all agent I/O
	if obj.Spec.ManagementPolicy != "Observe" && obj.Spec.ManagementPolicy != "Manage" && obj.Spec.ManagementPolicy != "" {
		return result, fmt.Errorf("invalid artifact management policy")
	}
	if err := r.checkArtifactClaims(ctx, obj); err != nil {
		return result, err
	}
	inputs := &resolvedInputReader{Reader: r.APIReader}
	bundle, err := resolveArtifactSources(ctx, inputs, obj, target)
	if err != nil {
		return result, err
	}
	if err = validateArtifactHostDeclaration(ctx, inputs, obj, bundle, sw); err != nil {
		return result, err
	}
	obj.Status.Identity = bundle.Identity()
	factory := r.NewClient
	if factory == nil {
		factory = newArtifactClient
	}
	connection, closer, err := factory(ctx, inputs, sw)
	if err != nil {
		return result, err
	}
	if connection == nil || closer == nil {
		return result, fmt.Errorf("artifact client unavailable")
	}
	defer func() { _ = closer.Close() }()
	// Capture the original declaration and Switch; status updates and reconnects
	// must not advance the authority used by the final admission callback.
	freshInputs := func(ctx context.Context) error {
		if err := r.artifactInputsFresh(ctx, original, sw, bundle); err != nil {
			return err
		}
		return inputs.fresh(ctx)
	}
	freshConnection, supportsFresh := connection.(agentclient.FreshArtifactClient)
	if obj.Spec.ManagementPolicy == "Manage" && !supportsFresh {
		return result, fmt.Errorf("artifact dispatch freshness capability unavailable")
	}
	if !r.ObserveOnly && r.AllowArtifacts && obj.Spec.ManagementPolicy == "Manage" {
		if bundle.Bootstrap == nil {
			return result, fmt.Errorf("immutable Kubernetes-owned bootstrap declaration required")
		}
		if err := freshInputs(ctx); err != nil {
			return result, err
		}
		bootstrap, err := freshConnection.ArtifactFresh(ctx, artifact.Request{Operation: "bootstrap", Bundle: bundle}, freshInputs)
		if err != nil {
			return result, err
		}
		if bootstrap == nil || !bootstrap.Configuration || !bootstrap.Runtime || !bootstrap.Persistence {
			return result, fmt.Errorf("bootstrap baseline is not enforced and healthy")
		}
	}
	current, err := connection.Artifact(ctx, artifact.Request{Operation: "observe", Bundle: bundle})
	if err != nil {
		return result, err
	}
	if current == nil {
		return result, fmt.Errorf("missing artifact observation")
	}
	artifactStatus(obj, current)
	if r.ObserveOnly || !r.AllowArtifacts || obj.Spec.ManagementPolicy != "Manage" {
		return result, nil
	}
	if current.Phase == "AwaitingConfirmation" && current.Identity == bundle.Identity() {
		// Discard the pre-restart transport. This handshake must validate the new
		// certificate and reach the restarted executable before confirmation.
		if err := closer.Close(); err != nil {
			return result, err
		}
		fresh, freshCloser, err := factory(ctx, inputs, sw)
		if err != nil {
			return result, err
		}
		if fresh == nil || freshCloser == nil {
			return result, fmt.Errorf("fresh artifact client unavailable")
		}
		defer func() { _ = freshCloser.Close() }()
		freshRPC, ok := fresh.(agentclient.FreshArtifactClient)
		if !ok {
			return result, fmt.Errorf("artifact dispatch freshness capability unavailable")
		}
		verified, err := fresh.Artifact(ctx, artifact.Request{Operation: "observe", Bundle: bundle})
		if err != nil {
			return result, err
		}
		if verified == nil || verified.Identity != bundle.Identity() || verified.Token != current.Token || verified.Phase != "AwaitingConfirmation" || !verified.Configuration || !verified.Runtime {
			return result, fmt.Errorf("fresh candidate health not verified")
		}
		if err := freshInputs(ctx); err != nil {
			return result, err
		}
		confirmed, err := freshRPC.ArtifactFresh(ctx, artifact.Request{Operation: "confirm", Bundle: bundle, Token: verified.Token}, freshInputs)
		if err != nil {
			return result, err
		}
		if confirmed == nil {
			return result, fmt.Errorf("missing artifact confirmation")
		}
		artifactStatus(obj, confirmed)
		return result, nil
	}
	if current.Phase == "Staged" || current.Phase == "Installing" || current.Phase == "Activating" || current.Phase == "Retiring" || current.Phase == "AwaitingConfirmation" || current.Phase == "RollingBack" || current.Phase == "RestoringAgent" || current.Phase == "WaitingForeign" || current.Phase == "RestoringBoot" || current.Phase == "ActivatingBoot" || current.Phase == "RecoveringBoot" {
		return result, nil
	}
	if current.Configuration && current.Runtime && current.Persistence && current.Phase == "Confirmed" && current.Identity == bundle.Identity() {
		return result, nil
	}
	if err := freshInputs(ctx); err != nil {
		return result, err
	}
	staged, err := freshConnection.ArtifactFresh(ctx, artifact.Request{Operation: "stage", Bundle: bundle}, freshInputs)
	if err != nil {
		return result, err
	}
	if staged == nil {
		return result, fmt.Errorf("missing artifact stage result")
	}
	artifactStatus(obj, staged)
	return result, nil
}
func (r *ArtifactReconciler) artifactInputsFresh(ctx context.Context, obj *api.SwitchArtifact, sw *api.Switch, bundle artifact.Bundle) error {
	latest := &api.SwitchArtifact{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(obj), latest); err != nil {
		return fmt.Errorf("artifact declaration unavailable before mutation")
	}
	if latest.UID != obj.UID || latest.Generation != obj.Generation || !latest.DeletionTimestamp.IsZero() || latest.Spec.ManagementPolicy != "Manage" || !reflect.DeepEqual(latest.Spec, obj.Spec) || latest.Status.Target != bundle.Target {
		return fmt.Errorf("artifact declaration changed before mutation")
	}
	latestSwitch := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(sw), latestSwitch); err != nil {
		return fmt.Errorf("artifact Switch unavailable before mutation")
	}
	target, _ := json.Marshal(struct {
		UID        string
		Management api.Management
	}{string(latestSwitch.UID), latestSwitch.Spec.Management})
	if !latestSwitch.DeletionTimestamp.IsZero() || artifact.Digest(target) != bundle.Target || !reflect.DeepEqual(latestSwitch.Spec, sw.Spec) {
		return fmt.Errorf("artifact target changed before mutation")
	}
	fresh, err := resolveArtifactSources(ctx, r.APIReader, latest, bundle.Target)
	if err != nil {
		return err
	}
	if fresh.Identity() != bundle.Identity() {
		return fmt.Errorf("artifact source identity changed before mutation")
	}
	if err := validateArtifactHostDeclaration(ctx, r.APIReader, latest, fresh, latestSwitch); err != nil {
		return err
	}
	return r.checkArtifactClaims(ctx, obj)
}

func (r *ArtifactReconciler) checkArtifactClaims(ctx context.Context, obj *api.SwitchArtifact) error {
	claims := &api.SwitchArtifactList{}
	if err := r.APIReader.List(ctx, claims); err != nil {
		return fmt.Errorf("artifact ownership unavailable")
	}
	for _, other := range claims.Items {
		if other.UID != obj.UID && other.Spec.SwitchName == obj.Spec.SwitchName && other.Spec.ManagementPolicy == "Manage" {
			return fmt.Errorf("conflicting artifact bundle owner")
		}
	}
	return nil
}
func artifactStatus(obj *api.SwitchArtifact, r *artifact.Result) {
	obj.Status.RecoveryReason = r.Reason
	obj.Status.ConfigurationVerified = r.Configuration
	obj.Status.RuntimeVerified = r.Runtime
	obj.Status.PersistenceVerified = r.Persistence
	obj.Status.RecoveryPhase = r.Phase
}
func newArtifactClient(ctx context.Context, reader client.Reader, sw *api.Switch) (artifactRPC, io.Closer, error) {
	a, err := switchutil.NewAgentClientFromSwitchRef(ctx, networkBoundReader{Reader: reader, target: sw}, &corev1.LocalObjectReference{Name: sw.Name}, "")
	if err != nil {
		return nil, nil, fmt.Errorf("artifact agent connection failed")
	}
	rpc, ok := a.(agentclient.ArtifactClient)
	closer, canClose := a.(io.Closer)
	if !ok || !canClose {
		_ = closeAgentClient(a)
		return nil, nil, fmt.Errorf("artifact agent capability unavailable")
	}
	return rpc, closer, nil
}

// artifactBlockedMessage bounds the reconcile error shown in conditions. Agent
// reasons are already filtered by the client before they reach this point.
func artifactBlockedMessage(err error) string {
	const limit = 512
	message := strings.TrimSpace(err.Error())
	if len(message) > limit {
		message = message[:limit] + "..."
	}
	return message
}
