// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func retainedManagementMatches(p host.NativeProfile, m host.Management, base string) bool {
	if len(p.LegacyMACHooks) == 0 {
		return true
	}
	if len(p.LegacyMACHooks) != 1 || m.MAC != "" || p.LegacyMACHooks[0].BaseMAC != base {
		return false
	}
	a, b := slices.Clone(m.Addresses), slices.Clone(p.LegacyMACHooks[0].Addresses)
	less := func(a, b host.Address) int {
		if a.Prefix < b.Prefix {
			return -1
		}
		if a.Prefix > b.Prefix {
			return 1
		}
		return 0
	}
	slices.SortFunc(a, less)
	slices.SortFunc(b, less)
	return m.Interface == "eth0" && reflect.DeepEqual(a, b)
}

func validateArtifactHostDeclaration(ctx context.Context, r client.Reader, obj *api.SwitchArtifact, b artifact.Bundle, sw *api.Switch) error {
	if b.Bootstrap == nil || b.Bootstrap.HostRecovery == nil || len(b.Bootstrap.HostRecovery.MACHooks) == 0 {
		return nil
	}
	p, err := host.ValidateNativeProfile(b.Bootstrap.HostRecovery.Profile)
	if err != nil {
		return err
	}
	list := &api.SwitchManagementList{}
	if err = r.List(ctx, list); err != nil {
		return err
	}
	matches := 0
	for _, o := range list.Items {
		if o.Spec.SwitchRef.Name != obj.Spec.SwitchName || !o.DeletionTimestamp.IsZero() {
			continue
		}
		m := host.Management{Interface: o.Spec.Interface, MAC: o.Spec.MAC}
		if m.Interface == "" {
			m.Interface = "eth0"
		}
		for _, a := range o.Spec.Addresses {
			m.Addresses = append(m.Addresses, host.Address{Prefix: string(a.Prefix), Gateway: string(a.Gateway)})
		}
		if !retainedManagementMatches(p, m, sw.Spec.MacAddress) {
			return fmt.Errorf("retained MAC profile conflicts with Management declaration")
		}
		matches++
	}
	if matches != 1 {
		return fmt.Errorf("retained MAC requires one matching Management declaration")
	}
	return nil
}

func validateHostRetainedSources(ctx context.Context, r client.Reader, switchName string, q host.Request) error {
	if r == nil {
		return host.ErrInvalid
	}
	list := &api.SwitchArtifactList{}
	if err := r.List(ctx, list); err != nil {
		return err
	}
	for _, o := range list.Items {
		if o.Spec.SwitchName != switchName || o.Spec.Bootstrap == nil || o.Spec.Bootstrap.HostRecovery == nil || len(o.Spec.Bootstrap.HostRecovery.MACHooks) == 0 {
			continue
		}
		b, err := resolveArtifactSources(ctx, r, &o, "host-declaration-check")
		if err != nil {
			return err
		}
		p, err := host.ValidateNativeProfile(b.Bootstrap.HostRecovery.Profile)
		if err != nil {
			return err
		}
		sw := &api.Switch{}
		if err = r.Get(ctx, client.ObjectKey{Name: switchName}, sw); err != nil {
			return err
		}
		if !retainedManagementMatches(p, *q.Management, sw.Spec.MacAddress) {
			return fmt.Errorf("management conflicts with retained MAC artifact")
		}
	}
	return nil
}
