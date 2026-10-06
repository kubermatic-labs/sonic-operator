// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Only a successful observation can carry this explicit, fresh agent contract.
// All ordinary claim, target freshness and process/resource gates still apply.
func networkBufferRepairEligible(obj client.Object, current *agent.NetworkResult) (bool, error) {
	if !current.BufferRepairEligible {
		return false, nil
	}
	if !current.Exists || current.RuntimeVerified {
		return false, fmt.Errorf("inconsistent buffer repair eligibility on absent or converged runtime")
	}
	switch o := obj.(type) {
	case *api.SwitchBufferPool, *api.SwitchBufferProfile, *api.SwitchBufferPG, *api.SwitchBufferQueue:
		return true, nil
	case *api.SwitchQoSMap:
		if o.Spec.Type == "TCToPriorityGroup" {
			return true, nil
		}
	case *api.SwitchQoSBinding:
		if o.Spec.TCToPriorityGroup != "" && o.Spec.DSCPToTC == "" && o.Spec.Dot1pToTC == "" && o.Spec.TCToQueue == "" && len(o.Spec.Queues) == 0 {
			return true, nil
		}
	}
	return false, fmt.Errorf("buffer repair eligibility on an unsupported resource")
}
