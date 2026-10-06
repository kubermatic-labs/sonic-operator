// SPDX-License-Identifier: Apache-2.0

package types

// EVPNMappingSnapshot is resolved from a same-switch Kubernetes reference.
// Agents independently check its configuration and durable ownership; the
// payload alone is neither API-server freshness nor hardware evidence.
type EVPNMappingSnapshot struct {
	Name               string   `json:"name"`
	UID                string   `json:"uid"`
	Generation         int64    `json:"generation"`
	Tunnel             string   `json:"tunnel"`
	VLANID             uint32   `json:"vlanID"`
	VNI                uint32   `json:"vni"`
	RouteDistinguisher string   `json:"routeDistinguisher"`
	ImportRouteTargets []string `json:"importRouteTargets"`
	ExportRouteTargets []string `json:"exportRouteTargets"`
}
