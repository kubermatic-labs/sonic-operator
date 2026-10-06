// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestSaveConfigViaDBus(t *testing.T) {
	t.Parallel()
	const output = "sensitive config output"
	for _, tc := range []struct {
		name    string
		body    []any
		callErr error
		wantErr string
	}{
		{name: "zero exit code", body: []any{int32(0), output}},
		{name: "nonzero exit code without D-Bus error", body: []any{int32(1), output}, wantErr: "exit code 1"},
		{name: "negative exit code", body: []any{int32(-1), output}, wantErr: "exit code -1"},
		{name: "empty reply", wantErr: "failed to save config via D-Bus"},
		{name: "missing output", body: []any{int32(0)}, wantErr: "failed to save config via D-Bus"},
		{name: "extra value", body: []any{int32(0), output, true}, wantErr: "failed to save config via D-Bus"},
		{name: "invalid exit code type", body: []any{"0", output}, wantErr: "failed to save config via D-Bus"},
		{name: "invalid output type", body: []any{int32(0), false}, wantErr: "failed to save config via D-Bus"},
		{name: "transport failure", callErr: errors.New("transport unavailable"), wantErr: "transport unavailable"},
		{name: "canceled call", callErr: context.Canceled, wantErr: context.Canceled.Error()},
		{name: "deadline exceeded", callErr: context.DeadlineExceeded, wantErr: context.DeadlineExceeded.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			calls := 0
			status := saveConfigViaDBus(ctx, func(gotCtx context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
				calls++
				if gotCtx != ctx {
					t.Error("D-Bus call did not receive the request context")
				}
				if method != "org.SONiC.HostService.config.save" || flags != 0 || len(args) != 1 || args[0] != "" {
					t.Errorf("unexpected D-Bus call: method=%q flags=%v args=%v", method, flags, args)
				}
				return &dbus.Call{Body: tc.body, Err: tc.callErr}
			})
			if calls != 1 {
				t.Errorf("D-Bus calls=%d, want 1", calls)
			}
			if tc.wantErr == "" {
				if status != nil {
					t.Fatalf("successful save returned %v", status)
				}
				return
			}
			if status == nil || status.Code != agenterrors.BAD_REQUEST || !strings.Contains(status.Message, tc.wantErr) {
				t.Fatalf("status=%v, want failure containing %q", status, tc.wantErr)
			}
			if strings.Contains(status.Message, output) {
				t.Error("save failure exposed command output")
			}
		})
	}
}

func TestSaveConfigViaDBusCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	status := saveConfigViaDBus(ctx, func(gotCtx context.Context, _ string, _ dbus.Flags, _ ...any) *dbus.Call {
		if gotCtx != ctx {
			t.Fatal("D-Bus call did not receive the cancellable context")
		}
		cancel()
		return &dbus.Call{Err: gotCtx.Err()}
	})
	if status == nil || status.Code == 0 || !strings.Contains(status.Message, context.Canceled.Error()) {
		t.Fatalf("canceled save returned %v", status)
	}
}

func TestSaveConfigLockedAlreadyCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	m := &SonicAgent{saveConfig: func(context.Context) *agent.Status {
		t.Fatal("canceled request must not attempt to save")
		return nil
	}}
	status := m.saveConfigLocked(ctx)
	if status == nil || status.Code != agenterrors.SERVER_ERROR || !strings.Contains(status.Message, context.Canceled.Error()) {
		t.Fatalf("already canceled save returned %v", status)
	}
}
