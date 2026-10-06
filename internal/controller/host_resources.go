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

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
		q.Kind = "Management"
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
			q.System.SNMP = &host.SNMP{Location: o.Spec.SNMP.Location, Contact: o.Spec.SNMP.Contact}
		}
		if o.Spec.SNMP != nil && o.Spec.SNMP.CommunitySecretRef != nil {
			ref := o.Spec.SNMP.CommunitySecretRef
			if r.APIReader == nil || len(validation.IsDNS1123Label(ref.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || len(validation.IsConfigMapKey(ref.Key)) != 0 {
				return q, fresh, host.ErrInvalid
			}
			secret := &corev1.Secret{}
			key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
			if fresh.Get(ctx, key, secret) != nil {
				return q, fresh, fmt.Errorf("host Secret reference could not be resolved")
			}
			value, ok := secret.Data[ref.Key]
			if !ok || len(value) == 0 || secret.UID == "" || secret.ResourceVersion == "" || !secret.DeletionTimestamp.IsZero() {
				return q, fresh, fmt.Errorf("host Secret key unavailable")
			}
			q.System.SNMP = &host.SNMP{Location: o.Spec.SNMP.Location, Contact: o.Spec.SNMP.Contact, Community: host.Credential(value)}
			identity := sha256.Sum256([]byte(string(secret.UID) + "/" + secret.ResourceVersion))
			q.Revision += "-" + hex.EncodeToString(identity[:])
		}
	default:
		return q, fresh, host.ErrInvalid
	}
	return q, fresh, host.ValidateRequest(q)
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
