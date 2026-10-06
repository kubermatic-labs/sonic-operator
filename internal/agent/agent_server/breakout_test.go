// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type breakoutBackend struct {
	switchAgent.SwitchAgent
	result  *agent.PortBreakout
	st      *agent.Status
	port    string
	request *agent.PortBreakoutRequest
	calls   int
}

func (b *breakoutBackend) GetPortBreakout(_ context.Context, port string) (*agent.PortBreakout, *agent.Status) {
	b.calls++
	b.port = port
	return b.result, b.st
}

func (b *breakoutBackend) ReconcilePortBreakout(_ context.Context, request *agent.PortBreakoutRequest) (*agent.PortBreakout, *agent.Status) {
	b.calls++
	b.request = request
	return b.result, b.st
}

func TestPortBreakoutProxy(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		result   *agent.PortBreakout
		st       *agent.Status
		wantCode codes.Code
	}{
		{name: "nil result", wantCode: codes.Internal},
		{name: "backend error", st: &agent.Status{Code: 409, Message: "pending breakout"}},
		{name: "complete result", result: &agent.PortBreakout{Port: "Ethernet0", Mode: "4x25G", SupportedModes: []string{"1x100G", "4x25G"}, Children: []agent.PortBreakoutChild{{Name: "Ethernet0", Lanes: "1", Speed: "25000", AdminState: "down", MTU: "9100"}}, RuntimeVerified: true, PersistenceVerified: true, Pending: true, Message: "recovery details"}},
		{name: "explicit success status", result: &agent.PortBreakout{Port: "Ethernet0"}, st: &agent.Status{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &breakoutBackend{result: tt.result, st: tt.st}
			s := NewProxyServer(b)
			for _, method := range []struct {
				name string
				call func() (*pb.PortBreakoutResponse, error)
			}{
				{"get", func() (*pb.PortBreakoutResponse, error) {
					return s.GetPortBreakout(t.Context(), &pb.GetPortBreakoutRequest{Port: "Ethernet0"})
				}},
				{"reconcile", func() (*pb.PortBreakoutResponse, error) {
					return s.ReconcilePortBreakout(t.Context(), &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"})
				}},
			} {
				t.Run(method.name, func(t *testing.T) {
					got, err := method.call()
					if status.Code(err) != tt.wantCode {
						t.Fatalf("response=%v error=%v, want %v", got, err, tt.wantCode)
					}
					if err != nil {
						return
					}
					if tt.st != nil && tt.st.Code != 0 {
						if got.GetStatus().GetCode() != tt.st.Code || got.GetStatus().GetMessage() != tt.st.Message {
							t.Fatalf("lost backend error: %v", got)
						}
						return
					}
					if got.GetStatus() == nil || got.Status.Code != 0 || got.Result == nil {
						t.Fatalf("missing success result: %v", got)
					}
					r := got.Result
					want := tt.result
					if r.Port != want.Port || r.Mode != want.Mode || !reflect.DeepEqual(r.SupportedModes, want.SupportedModes) || r.RuntimeVerified != want.RuntimeVerified || r.PersistenceVerified != want.PersistenceVerified || r.Pending != want.Pending || r.Message != want.Message || len(r.Children) != len(want.Children) {
						t.Fatalf("lost result fields: %v, want %+v", r, want)
					}
					for i, child := range r.Children {
						if (agent.PortBreakoutChild{Name: child.Name, Lanes: child.Lanes, Speed: child.Speed, AdminState: child.AdminState, MTU: child.Mtu}) != want.Children[i] {
							t.Fatalf("lost child fields: %v", child)
						}
					}
				})
			}
			if b.calls != 2 || b.port != "Ethernet0" || !reflect.DeepEqual(b.request, &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"}) {
				t.Fatalf("incorrect dispatch: %+v", b)
			}
		})
	}
}

func TestPortBreakoutProxyRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	b := &breakoutBackend{}
	s := NewProxyServer(b)
	for _, tt := range []struct {
		name    string
		request *pb.PortBreakoutRequest
	}{
		{"nil", nil}, {"empty port", &pb.PortBreakoutRequest{Mode: "4x25G", ChildAdminState: "down"}},
		{"empty mode", &pb.PortBreakoutRequest{Port: "Ethernet0", ChildAdminState: "down"}},
		{"invalid state", &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "Up"}},
		{"missing state", &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.ReconcilePortBreakout(t.Context(), tt.request); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, req := range []*pb.GetPortBreakoutRequest{nil, {}} {
		if _, err := s.GetPortBreakout(t.Context(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("error=%v", err)
		}
	}
	if b.calls != 0 {
		t.Fatal("invalid request reached backend")
	}
	for _, backend := range []switchAgent.SwitchAgent{nil, nilReadBackend{}} {
		s := NewProxyServer(backend)
		if _, err := s.GetPortBreakout(t.Context(), &pb.GetPortBreakoutRequest{Port: "Ethernet0"}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("error=%v", err)
		}
		if _, err := s.ReconcilePortBreakout(t.Context(), &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "up"}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("error=%v", err)
		}
	}
}

type breakoutJournalBackend struct {
	dir   string
	err   error
	calls int
}

func (b *breakoutJournalBackend) ConfigureBreakoutJournal(dir string) error {
	b.dir = dir
	b.calls++
	return b.err
}

func TestConfigureBreakoutJournal(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name            string
		dir             string
		allow, readOnly bool
		backendErr      error
		wantError       string
		wantCalls       int
	}{
		{name: "disabled"},
		{name: "read-only", allow: true, readOnly: true},
		{name: "enabled requires directory", allow: true, wantError: "--breakout-journal-dir"},
		{name: "relative directory", dir: "relative", allow: true, wantError: "absolute"},
		{name: "enabled", dir: "/private/journal", allow: true, wantCalls: 1},
		{name: "read-only recovery inspection", dir: "/private/journal", readOnly: true, wantCalls: 1},
		{name: "backend rejects permissions", dir: "/private/journal", allow: true, backendErr: errors.New("directory is not private"), wantError: "directory is not private", wantCalls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &breakoutJournalBackend{err: tt.backendErr}
			err := configureBreakoutJournal(b, tt.dir, tt.allow, tt.readOnly)
			if tt.wantError == "" && err != nil || tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("error=%v, want %q", err, tt.wantError)
			}
			if tt.backendErr != nil && !errors.Is(err, tt.backendErr) {
				t.Fatalf("lost backend error: %v", err)
			}
			if b.calls != tt.wantCalls || b.calls > 0 && b.dir != tt.dir {
				t.Fatalf("unexpected configuration: %+v", b)
			}
		})
	}
	if err := configureBreakoutJournal(struct{}{}, "/private/journal", true, false); err == nil {
		t.Fatal("unsupported backend accepted")
	}
}
