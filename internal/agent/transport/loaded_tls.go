// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const LoadedTLSPath = "/run/sonic-operator-agent/loaded-tls.json"

type LoadedTLS struct {
	MaterialID  string `json:"materialID"`
	certPEM     []byte
	keyPEM      []byte
	caPEM       []byte
	Version     int      `json:"version"`
	PID         int      `json:"pid"`
	BootID      string   `json:"bootID"`
	StartTicks  string   `json:"startTicks"`
	Certificate string   `json:"certificate"`
	ClientCA    string   `json:"clientCA"`
	Chain       []string `json:"chain"`
}

func TLSDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func PublishLoadedTLS(filename string, proof *LoadedTLS) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return err
	}
	parts := strings.SplitN(string(stat), ")", 2)
	if len(parts) != 2 {
		return fmt.Errorf("process identity unavailable")
	}
	fields := strings.Fields(parts[1])
	if len(fields) < 20 {
		return fmt.Errorf("process identity unavailable")
	}
	copy := *proof
	copy.Version = 1
	copy.PID = os.Getpid()
	copy.BootID = strings.TrimSpace(string(boot))
	copy.StartTicks = fields[19]
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("private TLS receipt directory required")
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	copy.MaterialID = hex.EncodeToString(token)
	material := filepath.Join(dir, copy.MaterialID)
	if err := os.Mkdir(material, 0700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"tls.crt": proof.certPEM, "tls.key": proof.keyPEM, "ca.crt": proof.caPEM} {
		if err := os.WriteFile(filepath.Join(material, name), data, 0600); err != nil {
			return err
		}
	}
	data, _ := json.Marshal(copy)
	f, err := os.CreateTemp(dir, ".loaded-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	_ = f.Chmod(0600)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(name, filename); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
