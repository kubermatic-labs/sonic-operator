// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Target fields only: unknown fields (including secrets on the same hash) stay
// in memory. Full CONFIG_DB fingerprints bind pending recovery and persistence.
type networkRecord struct {
	Kind        string             `json:"kind"`
	OwnerID     string             `json:"owner_id"`
	Fields      vlanChangeDB       `json:"fields"`
	Owned       vlanChangeDB       `json:"owned"`
	Fingerprint string             `json:"fingerprint"`
	Pending     *networkPending    `json:"pending,omitempty"`
	BufferProof *bufferNativeProof `json:"buffer_proof,omitempty"`
	// Global EVPN's declared set authorizes mapping creation during local-only
	// initialization. Omitted on legacy records, which cannot authorize it.
	EVPNMappings []agent.EVPNMappingSnapshot `json:"evpn_mappings,omitempty"`
	// Fixed port layout at adoption; a breakout cannot authorize restoring a
	// previously qualified speed/FEC on a different set of physical lanes.
	PortLayout string `json:"port_layout,omitempty"`
}

type networkPending struct {
	Request       agent.NetworkRequest `json:"request"`
	Activation    string               `json:"activation,omitempty"`
	Before        vlanChangeDB         `json:"before"`
	After         vlanChangeDB         `json:"after"`
	Owned         vlanChangeDB         `json:"owned"`
	PreHash       string               `json:"pre_hash"`
	PostHash      string               `json:"post_hash"`
	BufferProof   *bufferNativeProof   `json:"buffer_proof,omitempty"`
	BufferReapply bool                 `json:"buffer_reapply,omitempty"`
}

type networkJournalState struct {
	Checksum string                    `json:"checksum"`
	Version  int                       `json:"version"`
	Records  map[string]*networkRecord `json:"records"`
}

// ConfigureNetworkJournal is startup-only. All cooperating writers must keep
// this same private persistent path configured, including when writes are disabled.
func (m *SonicAgent) ConfigureNetworkJournal(dir string) error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("network journal requires an absolute persistent path")
	}
	dir = filepath.Clean(dir)
	if dir == m.journalDir || dir == m.breakoutJournalDir {
		return fmt.Errorf("network, VLAN and breakout journals require separate directories")
	}
	if m.networkJournalDir != "" && m.networkJournalDir != dir {
		return fmt.Errorf("network journal already configured")
	}
	j := &SonicAgent{}
	if err := j.ConfigureVLANAuthorityJournal(dir); err != nil {
		return err
	}
	m.networkJournalDir = dir
	return nil
}

func (m *SonicAgent) lockNetworkJournal(ctx context.Context) (*vlanAuthorityJournal, error) {
	if m.networkJournalDir == "" {
		return nil, fmt.Errorf("network journal is not configured")
	}
	j := &SonicAgent{journalDir: m.networkJournalDir, journalSync: m.journalSync, artifactStateDir: m.artifactStateDir}
	return j.lockVLANAuthorityJournal(ctx)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func loadNetworkJournal(j *vlanAuthorityJournal) (*networkJournalState, error) {
	dir, err := j.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() == "frr-migration" {
			if err := frrMigrationValidateStorage(filepath.Join(j.root.Name(), "frr-migration")); err != nil {
				return nil, err
			}
			continue
		}
		if entry.Name() == "relay-runtime" {
			if err := routingRelayValidateStorage(filepath.Join(j.root.Name(), "relay-runtime")); err != nil {
				return nil, err
			}
			continue
		}
		if entry.Name() != ".lock" && entry.Name() != "network.json" && entry.Name() != "network.json.tmp" {
			return nil, fmt.Errorf("unrecognized network journal entry; inspect before writes")
		}
	}
	f, err := j.root.OpenFile("network.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return &networkJournalState{Version: 1, Records: map[string]*networkRecord{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := vlanAuthoritySecure(info, false); err != nil {
		return nil, err
	}
	var state networkJournalState
	d := json.NewDecoder(io.LimitReader(f, 16<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&state); err != nil {
		return nil, fmt.Errorf("invalid network journal: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing or oversized network journal")
	}
	checksum := state.Checksum
	state.Checksum = ""
	data, err := json.Marshal(state)
	if err != nil || checksum != vlanChangeHash(data) {
		return nil, fmt.Errorf("network journal checksum mismatch")
	}
	state.Checksum = checksum
	if state.Version != 1 || state.Records == nil {
		return nil, fmt.Errorf("invalid network journal version/records")
	}
	pending := 0
	for identity, r := range state.Records {
		if identity == "" || len(identity) > 1024 || r == nil || r.OwnerID == "" || len(r.OwnerID) > 256 {
			return nil, fmt.Errorf("invalid network journal identity")
		}
		if r.PortLayout != "" && (r.Kind != "Port" || !vlanAuthorityDigestValid(r.PortLayout)) {
			return nil, fmt.Errorf("invalid port layout journal")
		}
		if len(r.EVPNMappings) > 64 || len(r.EVPNMappings) > 0 && (r.Kind != "EVPN" || identity != "EVPN|default") {
			return nil, fmt.Errorf("invalid journal EVPN mapping declaration")
		}
		mappingNames, mappingUIDs := map[string]bool{}, map[string]bool{}
		for _, ref := range r.EVPNMappings {
			if ref.Name == "" || ref.UID == "" || ref.Generation < 1 || mappingNames[ref.Name] || mappingUIDs[ref.UID] {
				return nil, fmt.Errorf("invalid journal EVPN mapping reference")
			}
			mappingNames[ref.Name], mappingUIDs[ref.UID] = true, true
		}
		if r.Fields != nil {
			if err := validateNetworkFields(r.Kind, r.Fields); err != nil {
				return nil, err
			}
			if !vlanAuthorityDigestValid(r.Fingerprint) || !networkSubset(r.Fields, r.Owned) {
				return nil, fmt.Errorf("invalid confirmed network ownership")
			}
		} else if r.Pending == nil || r.Fingerprint != "" {
			return nil, fmt.Errorf("missing confirmed network state")
		}
		if r.BufferProof != nil {
			if !reflect.DeepEqual(r.Fields, r.Owned) {
				return nil, fmt.Errorf("qualified buffer record does not own all declared fields")
			}
			if !bufferProofKind(r.Kind, r.Fields) {
				return nil, fmt.Errorf("native buffer proof on unsupported resource")
			}
			if err := r.BufferProof.validate(r.Fields); err != nil {
				return nil, err
			}
		}
		if p := r.Pending; p != nil {
			if r.BufferProof != nil && (p.BufferProof == nil || p.BufferProof.Fingerprint != r.BufferProof.Fingerprint) {
				return nil, fmt.Errorf("pending buffer operation changed its qualified native identity")
			}
			if p.BufferProof != nil {
				if !reflect.DeepEqual(p.After, p.Owned) {
					return nil, fmt.Errorf("qualified pending buffer does not own all declared fields")
				}
				if !bufferProofKind(r.Kind, p.After) {
					return nil, fmt.Errorf("pending native buffer proof on unsupported resource")
				}
				if err := p.BufferProof.validate(p.After); err != nil {
					return nil, err
				}
			}
			if p.BufferReapply && p.BufferProof == nil {
				return nil, fmt.Errorf("buffer reapply lacks native qualification")
			}
			pending++
			id, err := networkIdentity(&p.Request)
			if err != nil || id != identity || p.Request.Kind != r.Kind || p.Request.OwnerID != r.OwnerID || agent.ValidateNetworkRequest(&p.Request, true) != nil {
				return nil, fmt.Errorf("invalid pending network request identity")
			}
			switch p.Activation {
			case "", "Prepared", "Dispatched", "Verified":
			default:
				return nil, fmt.Errorf("invalid network activation phase")
			}
			if p.Before == nil || !vlanAuthorityDigestValid(p.PreHash) || !vlanAuthorityDigestValid(p.PostHash) {
				return nil, fmt.Errorf("invalid pending network fingerprints")
			}
			if err := validateNetworkFields(r.Kind, p.After); err != nil {
				return nil, err
			}
			if !networkSubset(p.After, p.Owned) {
				return nil, fmt.Errorf("invalid pending ownership")
			}
			for key, fields := range p.Before {
				for field := range fields {
					if _, ok := p.After[key][field]; !ok {
						return nil, fmt.Errorf("pending network deletion is forbidden")
					}
				}
			}
		}
	}
	if pending > 1 {
		return nil, fmt.Errorf("multiple pending network records; inspect before writes")
	}
	return &state, nil
}

func storeNetworkJournal(j *vlanAuthorityJournal, state *networkJournalState) error {
	old, err := loadNetworkJournal(j)
	if err != nil {
		return err
	}
	pending := false
	for _, record := range old.Records {
		pending = pending || record.Pending != nil
	}
	if err := j.artifactPublication(pending); err != nil {
		return err
	}
	if artifactstate.CheckPending(j.artifactDir) != nil {
		for identity, record := range state.Records {
			before := old.Records[identity]
			if before == nil {
				return artifactstate.ErrReserved
			}
			if record.Pending != nil && (before.Pending == nil || !reflect.DeepEqual(record.Pending.Request, before.Pending.Request)) {
				return artifactstate.ErrReserved
			}
		}
	}
	copy := *state
	copy.Checksum = ""
	data, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	copy.Checksum = vlanChangeHash(data)
	data, err = json.Marshal(copy)
	if err != nil {
		return err
	}
	if len(data) >= 16<<20 {
		return fmt.Errorf("network journal capacity exceeded")
	}
	const tmp = "network.json.tmp"
	if err := j.root.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := j.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
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
	if err := j.root.Rename(tmp, "network.json"); err != nil {
		return err
	}
	return j.sync()
}

// Caller holds configMutex and any VLAN/breakout locks. Hold through save.
func (m *SonicAgent) guardNetworkWrites(ctx context.Context) (func(), error) {
	_, unlock, err := m.guardNetworkWriteState(ctx)
	return unlock, err
}

// Return the validated state under the same lock so specialized writers can
// check confirmed ownership too. The caller must hold the lock through save.
func (m *SonicAgent) guardNetworkWriteState(ctx context.Context) (*networkJournalState, func(), error) {
	if err := m.artifactAdmission(ctx); err != nil {
		return nil, nil, err
	}
	if m.networkJournalDir == "" {
		if err := host.CheckPending(m.hostJournalDir); err != nil {
			return nil, nil, err
		}
		return nil, func() {}, nil
	}
	j, err := m.lockNetworkJournal(ctx)
	if err != nil {
		return nil, nil, err
	}
	state, err := loadNetworkJournal(j)
	if err == nil {
		err = m.artifactAdmission(ctx)
	}
	if err == nil {
		for _, r := range state.Records {
			if r.Pending != nil {
				err = fmt.Errorf("pending network persistence; reconcile its owner before other writes")
				break
			}
		}
	}
	if err != nil {
		j.close()
		return nil, nil, err
	}
	if err := host.CheckPending(m.hostJournalDir); err != nil {
		j.close()
		return nil, nil, err
	}
	return state, j.close, nil
}
