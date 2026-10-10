// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// hostKindManagement is the agent host request kind for SwitchManagement.
const hostKindManagement = "Management"

func hostObjects(kind string) (client.Object, client.ObjectList, error) {
	switch kind {
	case "Management":
		return &api.SwitchManagement{}, &api.SwitchManagementList{}, nil
	case "System":
		return &api.SwitchSystem{}, &api.SwitchSystemList{}, nil
	default:
		return nil, nil, host.ErrInvalid
	}
}
func hostFields(obj client.Object) (*api.NetworkResourceSpec, *api.HostResourceStatus) {
	switch o := obj.(type) {
	case *api.SwitchManagement:
		return &o.Spec.NetworkResourceSpec, &o.Status
	case *api.SwitchSystem:
		return &o.Spec.NetworkResourceSpec, &o.Status
	}
	panic("unsupported host resource")
}
func (r *HostReconciler) hostDesired(ctx context.Context, obj client.Object, target string) (host.Request, *resolvedInputReader, error) {
	common, _ := hostFields(obj)
	q := host.Request{Owner: string(obj.GetUID()), Target: target, Revision: strconv.FormatInt(obj.GetGeneration(), 10)}
	fresh := &resolvedInputReader{Reader: r.APIReader}
	if q.Owner == "" || len(validation.IsDNS1123Subdomain(common.SwitchRef.Name)) != 0 || (common.ManagementPolicy != "" && common.ManagementPolicy != api.NetworkManagementPolicyObserve && common.ManagementPolicy != api.NetworkManagementPolicyManage) {
		return q, fresh, host.ErrInvalid
	}
	switch o := obj.(type) {
	case *api.SwitchManagement:
		q.Kind = hostKindManagement
		q.Management = &host.Management{Interface: o.Spec.Interface, MAC: o.Spec.MAC}
		if q.Management.Interface == "" {
			q.Management.Interface = "eth0"
		}
		q.RollbackSeconds = o.Spec.RollbackSeconds
		if q.RollbackSeconds == 0 {
			q.RollbackSeconds = 120
		}
		for _, a := range o.Spec.Addresses {
			q.Management.Addresses = append(q.Management.Addresses, host.Address{Prefix: string(a.Prefix), Gateway: string(a.Gateway)})
		}
		if common.ManagementPolicy == api.NetworkManagementPolicyManage {
			if r.APIReader == nil {
				return q, fresh, host.ErrInvalid
			}
			if err := validateHostRetainedSources(ctx, fresh, common.SwitchRef.Name, q); err != nil {
				return q, fresh, err
			}
		}
	case *api.SwitchSystem:
		q.Kind = "System"
		q.System = &host.System{}
		if o.Spec.NTP != nil {
			q.System.NTP = &host.NTP{Servers: append([]string{}, o.Spec.NTP.Servers...), AdminState: o.Spec.NTP.AdminState, DHCP: o.Spec.NTP.DHCP, ServerRole: o.Spec.NTP.ServerRole, SourceInterface: o.Spec.NTP.SourceInterface}
		}
		if o.Spec.SNMP != nil {
			snmp, identities, err := r.hostSNMP(ctx, fresh, *o.Spec.SNMP)
			if err != nil {
				return q, fresh, err
			}
			q.System.SNMP = snmp
			// Secret identities, never values, join the public revision. A
			// community-only declaration keeps its historical revision.
			if len(identities) > 0 {
				identity := sha256.Sum256([]byte(strings.Join(identities, "\n")))
				q.Revision += "-" + hex.EncodeToString(identity[:])
			}
		}
	default:
		return q, fresh, host.ErrInvalid
	}
	return q, fresh, host.ValidateRequest(q)
}

func (r *HostReconciler) hostSNMP(ctx context.Context, fresh *resolvedInputReader, spec api.SystemSNMP) (*host.SNMP, []string, error) {
	snmp := &host.SNMP{Location: spec.Location, Contact: spec.Contact}
	var identities []string
	if spec.CommunitySecretRef != nil {
		value, identity, err := r.hostSecret(ctx, fresh, *spec.CommunitySecretRef)
		if err != nil {
			return nil, nil, err
		}
		snmp.Community = host.Credential(value)
		identities = append(identities, identity)
	}
	for _, u := range spec.Users {
		user := host.SNMPUser{Name: u.Name, SecurityLevel: u.SecurityLevel, AuthProtocol: u.AuthProtocol, PrivProtocol: u.PrivProtocol}
		if user.SecurityLevel == "" {
			user.SecurityLevel = host.SNMPAuthPriv
		}
		if user.AuthProtocol == "" {
			user.AuthProtocol = "SHA"
		}
		value, identity, err := r.hostSecret(ctx, fresh, u.AuthPasswordSecretRef)
		if err != nil {
			return nil, nil, err
		}
		user.AuthPassword = host.Credential(value)
		identities = append(identities, "user/"+u.Name+"/auth/"+identity)
		if user.SecurityLevel == host.SNMPAuthPriv {
			if user.PrivProtocol == "" {
				user.PrivProtocol = "AES"
			}
			if u.PrivPasswordSecretRef == nil {
				return nil, nil, host.ErrInvalid
			}
			value, identity, err = r.hostSecret(ctx, fresh, *u.PrivPasswordSecretRef)
			if err != nil {
				return nil, nil, err
			}
			user.PrivPassword = host.Credential(value)
			identities = append(identities, "user/"+u.Name+"/priv/"+identity)
		}
		snmp.Users = append(snmp.Users, user)
	}
	return snmp, identities, nil
}

// hostSecret resolves one Secret key through the reconciliation's identity-
// recording reader. Errors are fixed strings and never carry Secret content.
func (r *HostReconciler) hostSecret(ctx context.Context, fresh *resolvedInputReader, ref api.HostSecretKeyReference) ([]byte, string, error) {
	if r.APIReader == nil || len(validation.IsDNS1123Label(ref.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || len(validation.IsConfigMapKey(ref.Key)) != 0 {
		return nil, "", host.ErrInvalid
	}
	secret := &corev1.Secret{}
	if fresh.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret) != nil {
		return nil, "", fmt.Errorf("host Secret reference could not be resolved")
	}
	value, ok := secret.Data[ref.Key]
	if !ok || len(value) == 0 || secret.UID == "" || secret.ResourceVersion == "" || !secret.DeletionTimestamp.IsZero() {
		return nil, "", fmt.Errorf("host Secret key unavailable")
	}
	return value, string(secret.UID) + "/" + secret.ResourceVersion, nil
}

const hostBindingAnnotation = "sonic.networking.metal.ironcore.dev/host-target"

type hostBinding struct {
	UID, MAC, Host, Port string
	Credentials          corev1.ObjectReference
}

func bindingForHost(sw *api.Switch) hostBinding {
	return hostBinding{string(sw.UID), sw.Spec.MacAddress, sw.Spec.Management.Host, sw.Spec.Management.Port, sw.Spec.Management.Credentials}
}
func encodeHostBinding(b hostBinding) string { data, _ := json.Marshal(b); return string(data) }
func sameHostIdentity(a, b hostBinding) bool {
	return a.UID == b.UID && a.MAC == b.MAC && a.Port == b.Port && reflect.DeepEqual(a.Credentials, b.Credentials)
}
func candidateHost(q host.Request, current string) string {
	if q.Management == nil {
		return current
	}
	for _, a := range q.Management.Addresses {
		p, e := netip.ParsePrefix(a.Prefix)
		if e == nil && p.Addr().String() == current {
			return current
		}
	}
	p, e := netip.ParsePrefix(q.Management.Addresses[0].Prefix)
	if e != nil {
		return current
	}
	return p.Addr().String()
}
