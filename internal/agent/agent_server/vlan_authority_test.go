// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"errors"
	"reflect"
	"testing"

	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authorityBackend struct {
	switchAgent.SwitchAgent
	result  *agent.VLANAuthorityResult
	st      *agent.Status
	request *agent.VLANAuthorityRequest
	id      uint32
	owner   string
	calls   int
}

func (b *authorityBackend) GetVLANAuthority(_ context.Context, id uint32) (*agent.VLANAuthorityResult, *agent.Status) {
	b.calls++
	b.id = id
	return b.result, b.st
}

func (b *authorityBackend) ReconcileVLANAuthority(_ context.Context, request *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, *agent.Status) {
	b.calls++
	b.request = request
	return b.result, b.st
}

func (b *authorityBackend) ReleaseVLANAuthority(_ context.Context, id uint32, owner string) *agent.Status {
	b.calls++
	b.id, b.owner = id, owner
	return b.st
}

func TestVLANAuthorityServerResponses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		result *agent.VLANAuthorityResult
		st     *agent.Status
		code   codes.Code
	}{
		{name: "absent VLAN unknown ownership", result: &agent.VLANAuthorityResult{Digest: "absent-digest", OwnershipKnown: false}},
		{name: "absent VLAN known unowned", result: &agent.VLANAuthorityResult{Digest: "absent-digest", OwnershipKnown: true}},
		{name: "owned VLAN", result: &agent.VLANAuthorityResult{VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}}}, Digest: "digest", OwnerID: "owner", RuntimeVerified: true, PersistenceVerified: true}},
		{name: "pending persistence", result: &agent.VLANAuthorityResult{Digest: "digest", OwnerID: "owner", RuntimeVerified: true}},
		{name: "explicit success status", result: &agent.VLANAuthorityResult{Digest: "digest"}, st: &agent.Status{}},
		{name: "backend failure", st: &agent.Status{Code: 500, Message: "journal unavailable"}},
		{name: "nil result", code: codes.Internal},
		{name: "missing digest", result: &agent.VLANAuthorityResult{}, code: codes.Internal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &authorityBackend{result: tt.result, st: tt.st}
			s := NewProxyServer(b)
			for _, method := range []struct {
				name string
				call func() (*pb.VLANAuthorityResponse, error)
			}{
				{"get", func() (*pb.VLANAuthorityResponse, error) {
					return s.GetVLANAuthority(t.Context(), &pb.GetVLANAuthorityRequest{VlanId: 100})
				}},
				{"reconcile", func() (*pb.VLANAuthorityResponse, error) {
					return s.ReconcileVLANAuthority(t.Context(), &pb.VLANAuthorityRequest{OwnerId: "owner", Vlan: &pb.VLAN{Id: 100}})
				}},
			} {
				t.Run(method.name, func(t *testing.T) {
					got, err := method.call()
					if status.Code(err) != tt.code {
						t.Fatalf("error=%v, want %s", err, tt.code)
					}
					if tt.code != codes.OK {
						if got != nil {
							t.Fatal("result returned with error")
						}
						return
					}
					if tt.st != nil && tt.st.Code != 0 {
						if got.GetStatus().GetCode() != tt.st.Code || got.GetStatus().GetMessage() != tt.st.Message || got.GetResult() != nil {
							t.Fatalf("lost backend failure: %v", got)
						}
						return
					}
					r := got.GetResult()
					if r.GetOwnershipKnown() != tt.result.OwnershipKnown {
						t.Fatalf("ownership known=%v, want %v", r.GetOwnershipKnown(), tt.result.OwnershipKnown)
					}
					if got.GetStatus() == nil || got.Status.Code != 0 || r == nil || r.Digest != tt.result.Digest || r.OwnerId != tt.result.OwnerID || r.RuntimeVerified != tt.result.RuntimeVerified || r.PersistenceVerified != tt.result.PersistenceVerified {
						t.Fatalf("lost result fields: %v", got)
					}
					if (r.Vlan == nil) != (tt.result.VLAN == nil) {
						t.Fatal("lost absent VLAN")
					}
					if r.Vlan != nil && (r.Vlan.Id != 100 || len(r.Vlan.Members) != 1 || r.Vlan.Members[0].InterfaceName != "Ethernet0" || r.Vlan.Members[0].TaggingMode != "tagged") {
						t.Fatalf("lost VLAN: %v", r.Vlan)
					}
				})
			}
		})
	}
}

func TestVLANAuthorityServerRequests(t *testing.T) {
	t.Parallel()
	b := &authorityBackend{result: &agent.VLANAuthorityResult{Digest: "digest"}}
	s := NewProxyServer(b)
	want := &agent.VLANAuthorityRequest{OwnerID: "uid", AdoptionDigest: "adoption-digest", Delete: true, VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
	_, err := s.ReconcileVLANAuthority(t.Context(), &pb.VLANAuthorityRequest{OwnerId: want.OwnerID, AdoptionDigest: want.AdoptionDigest, Delete: want.Delete, Vlan: &pb.VLAN{Id: 100, Members: []*pb.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}})
	if err != nil || !reflect.DeepEqual(b.request, want) {
		t.Fatalf("request=%+v, error=%v", b.request, err)
	}
	for _, tt := range []struct {
		name    string
		request *pb.VLANAuthorityRequest
	}{
		{"nil", nil}, {"missing VLAN", &pb.VLANAuthorityRequest{OwnerId: "uid"}},
		{"missing owner", &pb.VLANAuthorityRequest{Vlan: &pb.VLAN{Id: 100}}},
		{"nil member", &pb.VLANAuthorityRequest{OwnerId: "uid", Vlan: &pb.VLAN{Id: 100, Members: []*pb.VLANMember{nil}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := b.calls
			if _, err := s.ReconcileVLANAuthority(t.Context(), tt.request); status.Code(err) != codes.InvalidArgument || b.calls != before {
				t.Fatalf("invalid request reached backend: %v", err)
			}
		})
	}
	if _, err := s.GetVLANAuthority(t.Context(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil get: %v", err)
	}
	for _, request := range []*pb.ReleaseVLANAuthorityRequest{nil, {VlanId: 100}} {
		before := b.calls
		if _, err := s.ReleaseVLANAuthority(t.Context(), request); status.Code(err) != codes.InvalidArgument || before != b.calls {
			t.Fatalf("invalid release: %v", err)
		}
	}
	for _, st := range []*agent.Status{nil, {}, {Code: 409, Message: "owner conflict"}} {
		b.st = st
		r, err := s.ReleaseVLANAuthority(t.Context(), &pb.ReleaseVLANAuthorityRequest{VlanId: 100, OwnerId: "uid"})
		if err != nil || r.GetStatus() == nil || b.id != 100 || b.owner != "uid" {
			t.Fatalf("release=%v, error=%v", r, err)
		}
		if st != nil && (r.Status.Code != st.Code || (st.Code != 0 && r.Status.Message != st.Message)) {
			t.Fatalf("lost status: %v", r)
		}
	}
}

func TestVLANAuthorityUnsupportedBackend(t *testing.T) {
	t.Parallel()
	s := NewProxyServer(nilReadBackend{})
	for _, tt := range []struct {
		name string
		call func() error
	}{
		{"get", func() error {
			_, err := s.GetVLANAuthority(t.Context(), &pb.GetVLANAuthorityRequest{VlanId: 100})
			return err
		}},
		{"reconcile", func() error {
			_, err := s.ReconcileVLANAuthority(t.Context(), &pb.VLANAuthorityRequest{OwnerId: "uid", Vlan: &pb.VLAN{Id: 100}})
			return err
		}},
		{"release", func() error {
			_, err := s.ReleaseVLANAuthority(t.Context(), &pb.ReleaseVLANAuthorityRequest{VlanId: 100, OwnerId: "uid"})
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); status.Code(err) != codes.Unimplemented {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type authorityJournalBackend struct {
	dir   string
	calls int
	err   error
}

func (b *authorityJournalBackend) ConfigureVLANAuthorityJournal(dir string) error {
	b.dir, b.calls = dir, b.calls+1
	return b.err
}

func TestConfigureVLANAuthorityJournal(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name            string
		allow, readOnly bool
		dir             string
		backendError    error
		wantError       bool
		calls           int
	}{
		{name: "default needs no journal"},
		{name: "read-only opt-in needs no journal", allow: true, readOnly: true},
		{name: "writes require explicit directory", allow: true, wantError: true},
		{name: "write journal", allow: true, dir: "/journal", calls: 1},
		{name: "configured read-only journal", readOnly: true, dir: "/journal", calls: 1},
		{name: "journal error aborts startup", allow: true, dir: "/journal", backendError: errors.New("directory must be root-only"), wantError: true, calls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &authorityJournalBackend{err: tt.backendError}
			err := configureVLANAuthorityJournal(b, tt.dir, tt.allow, tt.readOnly)
			if (err != nil) != tt.wantError || b.calls != tt.calls || (tt.calls > 0 && b.dir != tt.dir) {
				t.Fatalf("error=%v calls=%d dir=%s", err, b.calls, b.dir)
			}
			if tt.backendError != nil && !errors.Is(err, tt.backendError) {
				t.Fatalf("lost backend error: %v", err)
			}
		})
	}
	if err := configureVLANAuthorityJournal(struct{}{}, "/journal", false, true); err == nil {
		t.Fatal("configured unsupported backend")
	}
}
