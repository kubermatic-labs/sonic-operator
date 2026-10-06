// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

// Package transport loads the agent's mandatory, explicitly trusted TLS credentials.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

// LoadTLSConfig loads a certificate and a dedicated trust pool, never system roots.
// Servers must move RootCAs to ClientCAs and require verified client certificates.
func LoadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cfg, _, err := LoadTLSConfigWithEvidence(certFile, keyFile, caFile)
	return cfg, err
}
func LoadTLSConfigWithEvidence(certFile, keyFile, caFile string) (*tls.Config, *LoadedTLS, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, nil, fmt.Errorf("TLS certificate, key, and CA files are required")
	}
	certPEM, err := readTLSFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS certificate: %w", err)
	}
	keyPEM, err := readTLSFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS certificate and key: %w", err)
	}
	caPEM, err := readTLSFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("TLS CA file contains no valid certificates")
	}
	proof := &LoadedTLS{Version: 1, Certificate: TLSDigest(certPEM), ClientCA: TLSDigest(caPEM), certPEM: certPEM, keyPEM: keyPEM, caPEM: caPEM}
	for _, der := range cert.Certificate {
		proof.Chain = append(proof.Chain, TLSDigest(der))
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}, proof, nil
}

func readTLSFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("bounded TLS input unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return nil, fmt.Errorf("bounded TLS input required")
	}
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return nil, fmt.Errorf("bounded TLS input unreadable")
	}
	return b, nil
}
