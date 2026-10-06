// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
)

const (
	interfaceManageAdminAnnotation  = "sonic.networking.metal.ironcore.dev/manage-admin-state"
	interfaceAdminRequestAnnotation = "sonic.networking.metal.ironcore.dev/admin-state-request"
)

// The ordered JSON tuple is the external admin-intent digest contract. A request
// token supplies freshness for annotation-only changes, which have no new spec
// generation. It must be unique per adoption attempt; it is not a credential.
func interfaceAdminDigest(i *api.SwitchInterface, observeOnly bool) string {
	switchName := ""
	if i.Spec.SwitchRef != nil {
		switchName = i.Spec.SwitchRef.Name
	}
	data, _ := json.Marshal([]any{string(i.UID), i.Generation, switchName, i.Spec.Handle, i.Spec.NativeName, string(i.Spec.AdminState), i.Annotations[interfaceManageAdminAnnotation], i.Annotations[interfaceAdminRequestAnnotation], observeOnly})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
