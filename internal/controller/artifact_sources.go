// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"fmt"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func resolveArtifactSources(ctx context.Context, r client.Reader, obj *api.SwitchArtifact, target string) (artifact.Bundle, error) {
	b := artifact.Bundle{RetireLegacyHook: obj.Spec.RetireLegacyHook, Activation: obj.Spec.Activation, Owner: string(obj.UID), Target: target, Generation: obj.Generation, Baseline: obj.Spec.Baseline}
	if obj.Spec.Agent != nil {
		data, _ := json.Marshal(obj.Spec.Agent)
		b.Agent = &artifact.AgentOptions{}
		if err := json.Unmarshal(data, b.Agent); err != nil {
			return b, fmt.Errorf("invalid agent options")
		}
	}
	total := 0
	resolve := func(f api.ArtifactFile) (artifact.File, error) {
		out := artifact.File{Slot: f.Slot, SHA256: f.SHA256}
		if len(f.Chunks) < 1 || len(f.Chunks) > 256 {
			return out, fmt.Errorf("invalid artifact chunk count")
		}
		for _, ref := range f.Chunks {
			if ref.Name == "" || ref.UID == "" || ref.Key == "" {
				return out, fmt.Errorf("incomplete immutable artifact reference")
			}
			key := client.ObjectKey{Namespace: obj.Namespace, Name: ref.Name}
			var content []byte
			switch ref.Kind {
			case "ConfigMap":
				if artifact.SecretSlot(f.Slot) {
					return out, fmt.Errorf("certificate content requires Secret references")
				}
				source := &corev1.ConfigMap{}
				if err := r.Get(ctx, key, source); err != nil {
					return out, fmt.Errorf("artifact source unavailable")
				}
				if string(source.UID) != ref.UID || source.Immutable == nil || !*source.Immutable || !source.DeletionTimestamp.IsZero() {
					return out, fmt.Errorf("artifact source is mutable or replaced")
				}
				data, ok := source.BinaryData[ref.Key]
				text, textOK := source.Data[ref.Key]
				if ok && textOK {
					return out, fmt.Errorf("ambiguous artifact source key")
				}
				if textOK {
					data = []byte(text)
					ok = true
				}
				if !ok {
					return out, fmt.Errorf("artifact source key missing")
				}
				content = data
			case "Secret":
				if !artifact.SecretSlot(f.Slot) {
					return out, fmt.Errorf("Secret content is restricted to certificate slots")
				}
				source := &corev1.Secret{}
				if err := r.Get(ctx, key, source); err != nil {
					return out, fmt.Errorf("artifact Secret unavailable")
				}
				if string(source.UID) != ref.UID || source.Immutable == nil || !*source.Immutable || !source.DeletionTimestamp.IsZero() {
					return out, fmt.Errorf("artifact Secret is mutable or replaced")
				}
				data, ok := source.Data[ref.Key]
				if !ok {
					return out, fmt.Errorf("artifact Secret key missing")
				}
				content = data
			default:
				return out, fmt.Errorf("unsupported artifact source kind")
			}
			total += len(content)
			if total > artifact.MaxBundleBytes {
				return out, fmt.Errorf("artifact bundle too large")
			}
			out.Data = append(out.Data, content...)
		}
		if artifact.Digest(out.Data) != out.SHA256 {
			return out, fmt.Errorf("artifact source hash mismatch")
		}
		return out, nil
	}
	for _, f := range obj.Spec.Files {
		out, err := resolve(f)
		if err != nil {
			return b, err
		}
		b.Files = append(b.Files, out)
	}
	if spec := obj.Spec.Bootstrap; spec != nil {
		software := func(hash string, refs []api.ArtifactContentRef) ([]byte, error) {
			f, err := resolve(api.ArtifactFile{Slot: "AgentBinary", SHA256: hash, Chunks: refs})
			return f.Data, err
		}
		supervisor, err := software(spec.SupervisorSHA256, spec.SupervisorChunks)
		if err != nil {
			return b, err
		}
		policy, err := software(spec.PolicySHA256, []api.ArtifactContentRef{spec.PolicyRef})
		if err != nil {
			return b, err
		}
		b.Bootstrap = &artifact.Bootstrap{Supervisor: supervisor, SupervisorSHA256: spec.SupervisorSHA256, Policy: policy, PolicySHA256: spec.PolicySHA256, UnitSHA256: spec.UnitSHA256}
		if h := spec.HostRecovery; h != nil {
			out := &artifact.HostRecoveryBootstrap{BinarySHA256: h.BinarySHA256, ProfileSHA256: h.ProfileSHA256, ServiceSHA256: h.ServiceSHA256, TimerSHA256: h.TimerSHA256, ConfigSHA256: h.ConfigSHA256, JournalLayout: h.JournalLayout}
			out.Binary, err = software(h.BinarySHA256, h.BinaryChunks)
			if err != nil {
				return b, err
			}
			out.Profile, err = software(h.ProfileSHA256, []api.ArtifactContentRef{h.ProfileRef})
			if err != nil {
				return b, err
			}
			for _, m := range h.MACHooks {
				item := artifact.MACHookBootstrap{Kind: m.Kind, SourceHookSHA256: m.SourceHookSHA256, HelperSHA256: m.HelperSHA256}
				item.SourceHook, err = software(m.SourceHookSHA256, []api.ArtifactContentRef{m.SourceHookRef})
				if err != nil {
					return b, err
				}
				item.Helper, err = software(m.HelperSHA256, []api.ArtifactContentRef{m.HelperRef})
				if err != nil {
					return b, err
				}
				out.MACHooks = append(out.MACHooks, item)
			}
			b.Bootstrap.HostRecovery = out
		}
	}
	return b, b.Validate(true)
}
