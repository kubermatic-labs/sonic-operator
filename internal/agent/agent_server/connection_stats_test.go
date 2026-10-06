// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"testing"

	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/tap"
)

func TestCombinedStatsRetainsTransportAndLeaseThroughEnd(t *testing.T) {
	a := newArtifactAdmission()
	s := combinedStats{handlers: []stats.Handler{hostConnectionStats{}, a}}
	ctx := s.TagConn(t.Context(), &stats.ConnTagInfo{})
	id := hostConnection(ctx)
	ctx, err := a.tap(ctx, &tap.Info{FullMethodName: "/artifact.ArtifactService/UploadContent"})
	if err != nil {
		t.Fatal(err)
	}
	ctx = s.TagRPC(ctx, &stats.RPCTagInfo{})
	if hostConnection(ctx) != id || id == "" || len(a.slots) != 1 {
		t.Fatal("stats discarded context")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	s.HandleRPC(canceled, &stats.InHeader{})
	if len(a.slots) != 1 {
		t.Fatal("lease released before End")
	}
	s.HandleRPC(canceled, &stats.End{})
	if len(a.slots) != 0 {
		t.Fatal("End lost lease")
	}
}
