// SPDX-License-Identifier: Apache-2.0
package client

import (
	"encoding/pem"
	"fmt"

	"github.com/ironcore-dev/sonic-operator/internal/agent/transport"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func expectedArtifactChain(b artifact.Bundle) ([]string, bool, error) {
	for _, f := range b.Files {
		if f.Slot != "AgentCertificate" {
			continue
		}
		data := f.Data
		var chain []string
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				return nil, true, fmt.Errorf("invalid declared certificate chain")
			}
			data = rest
			if block.Type == "CERTIFICATE" {
				chain = append(chain, transport.TLSDigest(block.Bytes))
			}
		}
		return chain, true, nil
	}
	return nil, false, nil
}
func artifactPeerMatches(p peer.Peer, expected []string) bool {
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(expected) == 0 || len(info.State.PeerCertificates) != len(expected) {
		return false
	}
	for i, cert := range info.State.PeerCertificates {
		if transport.TLSDigest(cert.Raw) != expected[i] {
			return false
		}
	}
	return true
}
