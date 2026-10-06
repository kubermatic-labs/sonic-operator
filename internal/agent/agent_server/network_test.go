// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"encoding/json"
	"flag"
	"strings"
	"testing"

	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGroupedNetworkEnvelope(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"BufferPool", "BufferProfile", "BufferPG", "BufferQueue", "ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding", "MLAG", "VXLANTunnel", "VLANVNI", "EVPNPeer"} {
		t.Run(kind, func(t *testing.T) {
			for _, tc := range []struct {
				name, kind string
				valid      bool
			}{
				{"canonical", kind, true},
				{"lowercase", strings.ToLower(kind), false},
				{"space", kind + " ", false},
				{"null", kind + "\x00", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for _, write := range []bool{false, true} {
						err := agent.ValidateNetworkRequest(&agent.NetworkRequest{Kind: tc.kind, OwnerID: "uid", Spec: json.RawMessage(`{}`)}, write)
						if (err == nil) != tc.valid {
							t.Fatalf("write=%v err=%v", write, err)
						}
					}
				})
			}
		})
	}
}

func TestTrafficPolicyFlagDefaultsDisabled(t *testing.T) {
	t.Parallel()
	f := flag.Lookup("allow-traffic-policy")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("traffic policy must have an independent, default-disabled flag: %v", f)
	}
}

func TestRedundancyFlagDefaultsDisabled(t *testing.T) {
	t.Parallel()
	f := flag.Lookup("allow-redundancy")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("redundancy must have an independent, default-disabled flag: %v", f)
	}
}

func TestFRRMigrationEnvelope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind string
		valid      bool
	}{
		{"canonical", "FRRMigration", true},
		{"lowercase", "frrmigration", false},
		{"mixed case", "FrrMigration", false},
		{"uppercase", "FRRMIGRATION", false},
		{"space suffix", "FRRMigration ", false},
		{"null suffix", "FRRMigration\x00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, write := range []bool{false, true} {
				r := &agent.NetworkRequest{Kind: tc.kind, OwnerID: "uid", Spec: json.RawMessage(`{"mode":"Unified"}`)}
				if err := agent.ValidateNetworkRequest(r, write); (err == nil) != tc.valid {
					t.Fatalf("kind=%q write=%v err=%v", tc.kind, write, err)
				}
			}
		})
	}
}

func TestFRRMigrationFlagDefaultsDisabled(t *testing.T) {
	t.Parallel()
	f := flag.Lookup("allow-frr-migration")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("migration must have an independent, default-disabled flag: %v", f)
	}
}

type networkBackend struct {
	switchAgent.SwitchAgent
	result *agent.NetworkResult
	status *agent.Status
}

func (b networkBackend) GetNetworkResource(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	return b.result, b.status
}
func (b networkBackend) EnsureNetworkResource(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	return b.result, b.status
}

func TestNetworkServerValidation(t *testing.T) {
	t.Parallel()
	s := NewProxyServer(networkBackend{result: &agent.NetworkResult{ConfigurationVerified: true, Observed: json.RawMessage(`{}`)}, status: &agent.Status{Code: 500, Message: "save pending"}})
	for _, tc := range []struct {
		name    string
		request *pb.NetworkRequest
	}{
		{"nil", nil}, {"unknown kind", &pb.NetworkRequest{Kind: "CONFIG_DB", OwnerId: "uid", SpecJson: []byte(`{}`)}},
		{"missing owner", &pb.NetworkRequest{Kind: "VRF", SpecJson: []byte(`{}`)}},
		{"not object", &pb.NetworkRequest{Kind: "VRF", OwnerId: "uid", SpecJson: []byte(`[]`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.EnsureNetworkResource(t.Context(), tc.request); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err=%v", err)
			}
		})
	}
	r := &pb.NetworkRequest{Kind: "VRF", OwnerId: "uid", SpecJson: []byte(`{"name":"VrfTest"}`)}
	out, err := s.EnsureNetworkResource(t.Context(), r)
	if err != nil || out.GetStatus().GetCode() != 500 || !out.GetResult().GetConfigurationVerified() {
		t.Fatalf("lost error evidence: %+v %v", out, err)
	}
	if _, err := NewProxyServer(nilReadBackend{}).GetNetworkResource(t.Context(), r); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	if _, err := NewProxyServer(networkBackend{}).GetNetworkResource(t.Context(), r); status.Code(err) != codes.Internal {
		t.Fatal(err)
	}
}

type networkJournalBackend struct{ calls int }

func (b *networkJournalBackend) ConfigureNetworkJournal(string) error { b.calls++; return nil }
func TestNetworkJournalStartupOnly(t *testing.T) {
	b := &networkJournalBackend{}
	if err := configureNetworkJournal(b, "", true, false); err == nil {
		t.Fatal("missing journal accepted")
	}
	if err := configureNetworkJournal(b, "", true, true); err != nil {
		t.Fatal(err)
	}
	if err := configureNetworkJournal(b, "relative", false, true); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := configureNetworkJournal(b, "/private/network", false, true); err != nil || b.calls != 1 {
		t.Fatalf("configured disabled writer: %v calls=%d", err, b.calls)
	}
}

func TestNetworkServerBufferRepairEligibility(t *testing.T) {
	s := NewProxyServer(networkBackend{result: &agent.NetworkResult{Exists: true, ConfigurationVerified: true, PersistenceVerified: true, BufferRepairEligible: true}})
	out, err := s.GetNetworkResource(t.Context(), &pb.NetworkRequest{Kind: "BufferProfile", OwnerId: "owner", SpecJson: []byte(`{"name":"A"}`)})
	if err != nil || !out.GetResult().GetBufferRepairEligible() || out.GetResult().GetRuntimeVerified() || !out.GetResult().GetPersistenceVerified() {
		t.Fatalf("lost repair/persistence contract: %+v %v", out, err)
	}
}
