// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSSecretBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "private")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(65537)
	f.Close()
	_, _, err = LoadTLSConfigWithEvidence(p, p, p)
	if err == nil || !strings.Contains(err.Error(), "bounded") {
		t.Fatal("oversize TLS source not rejected before parsing", err)
	}
}
