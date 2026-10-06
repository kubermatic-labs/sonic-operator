// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"testing"

	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
)

func TestPortAdoptionProxyGuard(t *testing.T) {
	b := &breakoutBackend{result: &agent.PortBreakout{AdoptionSupported: true}}
	s := NewProxyServer(b)
	got, err := s.ReconcilePortBreakout(t.Context(), &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down", AdoptOnly: true})
	if err != nil || !b.request.AdoptOnly || !got.Result.AdoptionSupported {
		t.Fatalf("lost guard/capability: %+v %v %v", b.request, got, err)
	}
}

type adminEvidenceBackend struct{ switchAgent.SwitchAgent }

func (*adminEvidenceBackend) SetInterfaceAdminStatus(context.Context, *agent.Interface) (*agent.Interface, *agent.Status) {
	return &agent.Interface{NativeName: "Ethernet0", AdminStatus: agent.StatusUp, AdminPersistenceVerified: true}, nil
}

func TestPortAdoptionProxyAdminEvidence(t *testing.T) {
	s := NewProxyServer(&adminEvidenceBackend{})
	got, err := s.SetInterfaceAdminStatus(t.Context(), &pb.SetInterfaceAdminStatusRequest{InterfaceName: "Ethernet0", AdminStatus: "up"})
	if err != nil || !got.GetInterface().GetAdminPersistenceVerified() {
		t.Fatalf("lost evidence: %v %v", got, err)
	}
}
