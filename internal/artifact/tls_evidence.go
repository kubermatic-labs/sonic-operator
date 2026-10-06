// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/agent/transport"
)

func loadedTLSMatches(proof transport.LoadedTLS, pid int, boot, start, certificate, ca string) bool {
	return proof.Version == 1 && proof.PID == pid && proof.BootID == boot && proof.StartTicks == start && proof.Certificate == certificate && proof.ClientCA == ca
}
func (n *Native) loadedTLS() (*transport.LoadedTLS, error) {
	raw, mode, err := n.Engine.read(strings.TrimPrefix(transport.LoadedTLSPath, "/"))
	if err != nil || mode != 0600 {
		return nil, fmt.Errorf("TLS load receipt unavailable")
	}
	var proof transport.LoadedTLS
	if Decode(raw, &proof) != nil {
		return nil, fmt.Errorf("invalid TLS load receipt")
	}
	pidText := n.PID()
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid < 1 {
		return nil, fmt.Errorf("agent process unavailable")
	}
	raw, err = os.ReadFile("/proc/" + pidText + "/stat")
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(string(raw), ")", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid process identity")
	}
	fields := strings.Fields(parts[1])
	if len(fields) < 20 || proof.Version != 1 || proof.PID != pid || proof.BootID != n.BootID() || proof.StartTicks != fields[19] {
		return nil, fmt.Errorf("TLS load receipt belongs to another process")
	}
	if len(proof.MaterialID) != 32 {
		return nil, fmt.Errorf("invalid loaded material identity")
	}
	if _, err := hex.DecodeString(proof.MaterialID); err != nil {
		return nil, fmt.Errorf("invalid loaded material identity")
	}
	return &proof, nil
}
func (n *Native) PlanTLS(b Bundle) (bool, error) {
	cert, ca := "", ""
	for _, f := range b.Files {
		if f.Slot == "AgentCertificate" {
			cert = f.SHA256
		}
		if f.Slot == "AgentCA" {
			ca = f.SHA256
		}
	}
	if cert == "" && ca == "" {
		return false, nil
	}
	proof, err := n.loadedTLS()
	if err != nil {
		return true, nil
	}
	return proof.Certificate != cert || proof.ClientCA != ca, nil
}
func (n *Native) LoadedRecoveryInput(slot string) ([]byte, fs.FileMode, bool, error) {
	if !SecretSlot(slot) {
		return nil, 0, false, nil
	}
	proof, err := n.loadedTLS()
	if err != nil {
		return nil, 0, false, nil
	}
	name := map[string]string{"AgentCertificate": "tls.crt", "AgentKey": "tls.key", "AgentCA": "ca.crt"}[slot]
	data, _, err := n.Engine.read(path.Join("run/sonic-operator-agent", proof.MaterialID, name))
	if err != nil {
		return nil, 0, false, err
	}
	if slot == "AgentCertificate" && Digest(data) != proof.Certificate || slot == "AgentCA" && Digest(data) != proof.ClientCA {
		return nil, 0, false, fmt.Errorf("loaded TLS recovery content changed")
	}
	return data, 0600, true, nil
}
func (n *Native) verifyLoadedTLS(j *journal) error {
	cert, ca := "", ""
	for _, f := range j.Files {
		hash := f.Hash
		if j.Phase == "RollingBack" {
			hash = f.PreviousHash
		}
		if f.Slot == "AgentCertificate" {
			cert = hash
		}
		if f.Slot == "AgentCA" {
			ca = hash
		}
	}
	if cert == "" && ca == "" {
		return nil
	}
	proof, err := n.loadedTLS()
	if err != nil {
		return err
	}
	if proof.Certificate != cert || proof.ClientCA != ca {
		return fmt.Errorf("declared TLS inputs are not loaded")
	}
	return nil
}
