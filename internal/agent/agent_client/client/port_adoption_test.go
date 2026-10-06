// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
)

func TestPortAdoptionClientGuard(t *testing.T) {
	wire := &breakoutResponseClient{response: &pb.PortBreakoutResponse{Status: &pb.Status{}, Result: &pb.PortBreakout{AdoptionSupported: true}}}
	c := &defaultSwitchAgentClient{client: wire}
	got, err := c.ReconcilePortBreakout(t.Context(), &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down", AdoptOnly: true})
	if err != nil || !wire.request.AdoptOnly || !got.AdoptionSupported {
		t.Fatalf("adoption guard/evidence lost: %v %+v %v", wire.request, got, err)
	}
}

type adminEvidenceClient struct {
	pb.SwitchAgentServiceClient
	verified bool
}

func (c *adminEvidenceClient) SetInterfaceAdminStatus(context.Context, *pb.SetInterfaceAdminStatusRequest, ...grpc.CallOption) (*pb.SetInterfaceAdminStatusResponse, error) {
	return &pb.SetInterfaceAdminStatusResponse{Status: &pb.Status{}, Interface: &pb.Interface{NativeName: "Ethernet0", AdminStatus: "up", AdminPersistenceVerified: c.verified}}, nil
}

func TestPortAdoptionClientAdminEvidence(t *testing.T) {
	for _, verified := range []bool{false, true} {
		c := &defaultSwitchAgentClient{client: &adminEvidenceClient{verified: verified}}
		got, err := c.SetInterfaceAdminStatus(t.Context(), &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp, AdminPersistenceVerified: true})
		if err != nil || got.AdminPersistenceVerified != verified {
			t.Fatalf("lost or stale persistence evidence: %+v %v", got, err)
		}
	}
}
