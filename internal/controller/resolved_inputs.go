// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolvedInputReader records only identities, never source or credential bytes.
// Pass this same reader through every resolver and connection constructor for a
// reconciliation. Repeated reads cannot replace the initially accepted identity.
// It is local to the synchronous reconciliation, not a shared/cache reader.
type resolvedInputReader struct {
	client.Reader
	inputs map[resolvedInputKey]resolvedInputIdentity
}

type resolvedInputKey struct {
	client.ObjectKey
	secret bool
}

type resolvedInputIdentity struct {
	uid     types.UID
	version string
}

func (r *resolvedInputReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	input := resolvedInputKey{ObjectKey: key}
	switch obj.(type) {
	case *corev1.Secret:
		input.secret = true
	case *corev1.ConfigMap:
	default:
		return nil
	}
	identity := resolvedInputIdentity{uid: obj.GetUID(), version: obj.GetResourceVersion()}
	if identity.uid == "" || identity.version == "" || !obj.GetDeletionTimestamp().IsZero() {
		return fmt.Errorf("resolved input identity unavailable")
	}
	if prior, ok := r.inputs[input]; ok && prior != identity {
		return fmt.Errorf("resolved input changed during resolution")
	}
	if r.inputs == nil {
		r.inputs = make(map[resolvedInputKey]resolvedInputIdentity)
	}
	r.inputs[input] = identity
	return nil
}

func (r *resolvedInputReader) fresh(ctx context.Context) error {
	for key, identity := range r.inputs {
		var current client.Object = &corev1.ConfigMap{}
		if key.secret {
			current = &corev1.Secret{}
		}
		if r.Reader.Get(ctx, key.ObjectKey, current) != nil || current.GetUID() != identity.uid || current.GetResourceVersion() != identity.version || !current.GetDeletionTimestamp().IsZero() {
			return fmt.Errorf("resolved input changed before mutation")
		}
	}
	return nil
}
