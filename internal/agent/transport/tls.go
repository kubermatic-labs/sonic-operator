// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

// Package transport loads the agent's mandatory, explicitly trusted TLS credentials.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadTLSConfig loads a certificate and a dedicated trust pool, never system roots.
// Servers must move RootCAs to ClientCAs and require verified client certificates.
func LoadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, fmt.Errorf("TLS certificate, key, and CA files are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate and key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("TLS CA file contains no valid certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}, nil
}
