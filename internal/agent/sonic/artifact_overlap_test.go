// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

func TestArtifactRestartBoundaryAndForeignRecoveryDependency(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "host/sonic-operator-artifacts")
	m := &SonicAgent{journalDir: filepath.Join(root, "vlan"), breakoutJournalDir: filepath.Join(root, "breakout"), networkJournalDir: filepath.Join(root, "network"), artifactStateDir: dir}
	for _, p := range []string{m.journalDir, m.breakoutJournalDir, m.networkJournalDir} {
		_ = os.MkdirAll(p, 0700)
		_ = os.WriteFile(filepath.Join(p, ".lock"), nil, 0600)
	}
	fence := &ArtifactWriterFence{agent: m}
	fields := vlanChangeDB{"VRF|VrfTest": {"NULL": "NULL"}}
	pending := &networkJournalState{Version: 1, Records: map[string]*networkRecord{"VRF|VrfTest": {Kind: "VRF", OwnerID: "uid-1", Pending: &networkPending{Request: agent.NetworkRequest{Kind: "VRF", OwnerID: "uid-1", Spec: json.RawMessage(`{"name":"VrfTest"}`)}, Activation: "Prepared", Before: vlanChangeDB{}, After: fields, Owned: fields, PreHash: strings.Repeat("a", 64), PostHash: strings.Repeat("b", 64)}}}}
	j, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := storeNetworkJournal(j, pending); err != nil {
		t.Fatal(err)
	}
	foreign, _ := os.ReadFile(filepath.Join(m.networkJournalDir, "network.json"))
	_ = storeNetworkJournal(j, &networkJournalState{Version: 1, Records: map[string]*networkRecord{}})
	j.close()
	elf := make([]byte, 120)
	copy(elf, []byte{'\x7f', 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[16:], 2)
	binary.LittleEndian.PutUint16(elf[18:], 62)
	binary.LittleEndian.PutUint32(elf[20:], 1)
	binary.LittleEndian.PutUint64(elf[32:], 64)
	binary.LittleEndian.PutUint16(elf[52:], 64)
	binary.LittleEndian.PutUint16(elf[54:], 56)
	binary.LittleEndian.PutUint16(elf[56:], 1)
	binary.LittleEndian.PutUint32(elf[64:], 1)
	old := append([]byte(nil), elf...)
	old = append(old, []byte("old-working")...)
	binaryPath := filepath.Join(root, "usr/local/sbin/sonic-operator-agent")
	_ = os.MkdirAll(filepath.Dir(binaryPath), 0700)
	_ = os.WriteFile(binaryPath, old, 0755)
	health := func() error {
		data, _ := os.ReadFile(binaryPath)
		if artifact.Digest(data) != artifact.Digest(old) {
			return os.ErrInvalid
		}
		return nil
	}
	open := func() *artifact.Engine {
		info := releaseinfo.Current()
		info.SourceCommit = strings.Repeat("a", 40)
		e, err := artifact.Open(root, "/host/sonic-operator-artifacts", artifact.Policy{Baseline: "test", AgentBuilds: map[string]artifact.ReleaseBuild{artifact.Digest(old): info, artifact.Digest(elf): info}}, health, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		e.DeferActivation = true
		e.MutationGuard = func(ctx context.Context, fn func() error) error { return fence.WithMutation(ctx, fn) }
		e.AgentRecoveryGuard = func(ctx context.Context, owner, token, manifest string, fn func() error) error {
			return fence.WithAgentRecovery(ctx, owner, token, manifest, fn)
		}
		e.ActivateAgentRecovery = func() error { return nil }
		e.AgentRecoveryHealth = health
		return e
	}
	e := open()
	b := artifact.Bundle{Owner: "artifact-owner", Target: "switch", Baseline: "test", Generation: 1, Files: []artifact.File{{Slot: "AgentBinary", Data: elf, SHA256: artifact.Digest(elf)}}}
	seedArtifactAgentTLS(t, root, &b)
	now := time.Now()
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	if artifactstate.CheckPending(dir) != nil {
		t.Fatal("private staging blocked network writers")
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	// A request admitted before restart is rechecked at durable publication.
	j, err = m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := storeNetworkJournal(j, pending); err == nil {
		t.Fatal("restart-boundary request published after reservation")
	}
	j.close()
	// Simulate an already-published legacy foreign record, which must be preserved.
	_ = os.WriteFile(filepath.Join(m.networkJournalDir, "network.json"), foreign, 0600)
	e.Close()
	e = open()
	defer e.Close() // supervisor restart and controller loss
	_ = e.Tick(now.Add(6 * time.Minute))
	if err := health(); err != nil {
		t.Fatal("timed dependency recovery did not restore old agent")
	}
	got, _ := os.ReadFile(filepath.Join(m.networkJournalDir, "network.json"))
	if string(got) != string(foreign) {
		t.Fatal("artifact recovery altered foreign journal")
	}
	if artifactstate.CheckPending(dir) == nil {
		t.Fatal("new work admitted before foreign recovery")
	}
	if err := artifactstate.CheckRecovery(dir); err != nil {
		t.Fatal(err)
	}
	j, err = m.lockNetworkJournal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := storeNetworkJournal(j, &networkJournalState{Version: 1, Records: map[string]*networkRecord{}}); err != nil {
		t.Fatal(err)
	}
	j.close()
	if err := e.Tick(now.Add(7 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := artifactstate.CheckPending(dir); err != nil {
		t.Fatal("reservation not released after recovery")
	}
}

func seedArtifactAgentTLS(t *testing.T, root string, b *artifact.Bundle) {
	t.Helper()
	b.Agent = &artifact.AgentOptions{BindAddress: "192.0.2.1", Port: 50051, Artifacts: true, HostGuard: true}
	unit, _ := artifact.AgentUnit(*b.Agent)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for slot, data := range map[string][]byte{"AgentCertificate": cert, "AgentCA": cert, "AgentKey": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), "AgentUnit": unit} {
		p, m, _ := artifact.Destination(slot)
		if slot == "AgentUnit" {
			p = "etc/systemd/system/sonic-operator-agent.service"
			m = 0644
		} else {
			b.Files = append(b.Files, artifact.File{Slot: slot, Data: data, SHA256: artifact.Digest(data)})
		}
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, m); err != nil {
			t.Fatal(err)
		}
	}
}
