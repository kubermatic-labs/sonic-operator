//go:build integration

// SPDX-License-Identifier: Apache-2.0

package agent_server

import "google.golang.org/grpc"

func newGRPCServer(certFile, keyFile, clientCAFile string, readOnly bool, allowAuthoritative ...bool) (*grpc.Server, error) {
	return newGRPCServerWithBreakout(certFile, keyFile, clientCAFile, readOnly, len(allowAuthoritative) == 1 && allowAuthoritative[0], false)
}

func newGRPCServerWithBreakout(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout bool) (*grpc.Server, error) {
	return newGRPCServerWithNetwork(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, false)
}

func newGRPCServerWithNetwork(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork bool) (*grpc.Server, error) {
	return newGRPCServerWithFRRMigration(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, false)
}

// Migration always requires its own explicit opt-in, including for journal recovery.
func newGRPCServerWithFRRMigration(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration bool) (*grpc.Server, error) {
	return newGRPCServerWithTrafficPolicy(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, false)
}

// Traffic policy requires an independent opt-in for both Ensure and Recover.
func newGRPCServerWithTrafficPolicy(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic bool) (*grpc.Server, error) {
	return newGRPCServerWithRedundancy(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic, false)
}

// Redundancy requires an independent opt-in for both Ensure and Recover.
func newGRPCServerWithRedundancy(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic, allowRedundancy bool) (*grpc.Server, error) {
	server, _, err := newGRPCServerWithTLSProof(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic, allowRedundancy)
	return server, err
}
