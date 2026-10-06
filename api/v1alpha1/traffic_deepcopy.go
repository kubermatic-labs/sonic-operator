// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "k8s.io/apimachinery/pkg/runtime"

// Traffic deep copies are kept separate from the shared generated file so the
// traffic API can be compiled independently during concurrent API development.
func (in *ACLRule) DeepCopyInto(out *ACLRule) {
	*out = *in
	if in.Protocol != nil {
		out.Protocol = new(uint32)
		*out.Protocol = *in.Protocol
	}
	if in.SourcePort != nil {
		out.SourcePort = new(uint32)
		*out.SourcePort = *in.SourcePort
	}
	if in.DestinationPort != nil {
		out.DestinationPort = new(uint32)
		*out.DestinationPort = *in.DestinationPort
	}
}

func (in *SwitchACLPolicySpec) DeepCopyInto(out *SwitchACLPolicySpec) {
	*out = *in
	if in.Rules != nil {
		out.Rules = make([]ACLRule, len(in.Rules))
		for i := range in.Rules {
			in.Rules[i].DeepCopyInto(&out.Rules[i])
		}
	}
}

func (in *SwitchACLBindingSpec) DeepCopyInto(out *SwitchACLBindingSpec) {
	*out = *in
	if in.Interfaces != nil {
		out.Interfaces = append([]string{}, in.Interfaces...)
	}
}

func (in *SwitchQoSMapSpec) DeepCopyInto(out *SwitchQoSMapSpec) {
	*out = *in
	if in.Entries != nil {
		out.Entries = append([]QoSMapEntry{}, in.Entries...)
	}
}

func (in *SwitchSchedulerSpec) DeepCopyInto(out *SwitchSchedulerSpec) {
	*out = *in
	if in.Weight != nil {
		out.Weight = new(uint32)
		*out.Weight = *in.Weight
	}
	if in.CommittedRate != nil {
		out.CommittedRate = new(uint64)
		*out.CommittedRate = *in.CommittedRate
	}
	if in.PeakRate != nil {
		out.PeakRate = new(uint64)
		*out.PeakRate = *in.PeakRate
	}
	if in.CommittedBurst != nil {
		out.CommittedBurst = new(uint64)
		*out.CommittedBurst = *in.CommittedBurst
	}
	if in.PeakBurst != nil {
		out.PeakBurst = new(uint64)
		*out.PeakBurst = *in.PeakBurst
	}
}

func (in *SwitchQoSBindingSpec) DeepCopyInto(out *SwitchQoSBindingSpec) {
	*out = *in
	if in.Queues != nil {
		out.Queues = append([]QoSQueueBinding{}, in.Queues...)
	}
}

func (in *SwitchACLPolicy) DeepCopyInto(out *SwitchACLPolicy) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchACLPolicy) DeepCopy() *SwitchACLPolicy {
	if in == nil {
		return nil
	}
	out := new(SwitchACLPolicy)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchACLPolicy) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchACLPolicyList) DeepCopyInto(out *SwitchACLPolicyList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchACLPolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchACLPolicyList) DeepCopy() *SwitchACLPolicyList {
	if in == nil {
		return nil
	}
	out := new(SwitchACLPolicyList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchACLPolicyList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchACLBinding) DeepCopyInto(out *SwitchACLBinding) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchACLBinding) DeepCopy() *SwitchACLBinding {
	if in == nil {
		return nil
	}
	out := new(SwitchACLBinding)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchACLBinding) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchACLBindingList) DeepCopyInto(out *SwitchACLBindingList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchACLBinding, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchACLBindingList) DeepCopy() *SwitchACLBindingList {
	if in == nil {
		return nil
	}
	out := new(SwitchACLBindingList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchACLBindingList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchQoSMap) DeepCopyInto(out *SwitchQoSMap) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchQoSMap) DeepCopy() *SwitchQoSMap {
	if in == nil {
		return nil
	}
	out := new(SwitchQoSMap)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchQoSMap) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchQoSMapList) DeepCopyInto(out *SwitchQoSMapList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchQoSMap, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchQoSMapList) DeepCopy() *SwitchQoSMapList {
	if in == nil {
		return nil
	}
	out := new(SwitchQoSMapList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchQoSMapList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchScheduler) DeepCopyInto(out *SwitchScheduler) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchScheduler) DeepCopy() *SwitchScheduler {
	if in == nil {
		return nil
	}
	out := new(SwitchScheduler)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchScheduler) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchSchedulerList) DeepCopyInto(out *SwitchSchedulerList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchScheduler, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchSchedulerList) DeepCopy() *SwitchSchedulerList {
	if in == nil {
		return nil
	}
	out := new(SwitchSchedulerList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchSchedulerList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}

func (in *SwitchQoSBinding) DeepCopyInto(out *SwitchQoSBinding) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}
func (in *SwitchQoSBinding) DeepCopy() *SwitchQoSBinding {
	if in == nil {
		return nil
	}
	out := new(SwitchQoSBinding)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchQoSBinding) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
func (in *SwitchQoSBindingList) DeepCopyInto(out *SwitchQoSBindingList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SwitchQoSBinding, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SwitchQoSBindingList) DeepCopy() *SwitchQoSBindingList {
	if in == nil {
		return nil
	}
	out := new(SwitchQoSBindingList)
	in.DeepCopyInto(out)
	return out
}
func (in *SwitchQoSBindingList) DeepCopyObject() runtime.Object {
	if out := in.DeepCopy(); out != nil {
		return out
	}
	return nil
}
