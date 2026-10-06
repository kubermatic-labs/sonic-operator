// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"slices"

	"k8s.io/apimachinery/pkg/runtime"
)

// Separate copies allow concurrent workers to compile without shared generation.
func (in *SwitchMLAGSpec) DeepCopyInto(out *SwitchMLAGSpec) {
	*out = *in
	out.Members = slices.Clone(in.Members)
}
func (in *SwitchVXLANTunnelSpec) DeepCopyInto(out *SwitchVXLANTunnelSpec) { *out = *in }
func (in *SwitchVLANVNISpec) DeepCopyInto(out *SwitchVLANVNISpec) {
	*out = *in
	out.ImportRouteTargets = slices.Clone(in.ImportRouteTargets)
	out.ExportRouteTargets = slices.Clone(in.ExportRouteTargets)
}
func (in *SwitchEVPNPeerSpec) DeepCopyInto(out *SwitchEVPNPeerSpec) {
	*out = *in
	if in.ImportRouteTargets != nil {
		out.ImportRouteTargets = append([]RouteIdentifier{}, in.ImportRouteTargets...)
	}
	if in.ExportRouteTargets != nil {
		out.ExportRouteTargets = append([]RouteIdentifier{}, in.ExportRouteTargets...)
	}
	if in.MappingRefs != nil {
		out.MappingRefs = append([]NetworkSwitchReference{}, in.MappingRefs...)
	}
}

func (in *SwitchMLAG) DeepCopyInto(out *SwitchMLAG) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchMLAG) DeepCopy() *SwitchMLAG {
	if in == nil {
		return nil
	}
	out := new(SwitchMLAG)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchMLAG) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchMLAGList) DeepCopyInto(out *SwitchMLAGList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchMLAG, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchMLAGList) DeepCopy() *SwitchMLAGList {
	if in == nil {
		return nil
	}
	out := new(SwitchMLAGList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchMLAGList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchVXLANTunnel) DeepCopyInto(out *SwitchVXLANTunnel) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchVXLANTunnel) DeepCopy() *SwitchVXLANTunnel {
	if in == nil {
		return nil
	}
	out := new(SwitchVXLANTunnel)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchVXLANTunnel) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchVXLANTunnelList) DeepCopyInto(out *SwitchVXLANTunnelList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchVXLANTunnel, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchVXLANTunnelList) DeepCopy() *SwitchVXLANTunnelList {
	if in == nil {
		return nil
	}
	out := new(SwitchVXLANTunnelList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchVXLANTunnelList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchVLANVNI) DeepCopyInto(out *SwitchVLANVNI) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchVLANVNI) DeepCopy() *SwitchVLANVNI {
	if in == nil {
		return nil
	}
	out := new(SwitchVLANVNI)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchVLANVNI) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchVLANVNIList) DeepCopyInto(out *SwitchVLANVNIList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchVLANVNI, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchVLANVNIList) DeepCopy() *SwitchVLANVNIList {
	if in == nil {
		return nil
	}
	out := new(SwitchVLANVNIList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchVLANVNIList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchEVPNPeer) DeepCopyInto(out *SwitchEVPNPeer) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchEVPNPeer) DeepCopy() *SwitchEVPNPeer {
	if in == nil {
		return nil
	}
	out := new(SwitchEVPNPeer)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchEVPNPeer) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchEVPNPeerList) DeepCopyInto(out *SwitchEVPNPeerList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchEVPNPeer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchEVPNPeerList) DeepCopy() *SwitchEVPNPeerList {
	if in == nil {
		return nil
	}
	out := new(SwitchEVPNPeerList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchEVPNPeerList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
