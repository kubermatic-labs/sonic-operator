// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"fmt"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

type HostRecoveryBootstrap struct {
	BinarySHA256  string             `json:"binarySHA256"`
	Binary        []byte             `json:"binary,omitempty"`
	ProfileSHA256 string             `json:"profileSHA256"`
	Profile       []byte             `json:"profile,omitempty"`
	ServiceSHA256 string             `json:"serviceSHA256"`
	TimerSHA256   string             `json:"timerSHA256"`
	ConfigSHA256  string             `json:"configSHA256"`
	JournalLayout string             `json:"journalLayout"`
	MACHooks      []MACHookBootstrap `json:"macHooks,omitempty"`
}
type MACHookBootstrap struct {
	Kind             string `json:"kind"`
	SourceHookSHA256 string `json:"sourceHookSHA256"`
	SourceHook       []byte `json:"sourceHook,omitempty"`
	HelperSHA256     string `json:"helperSHA256"`
	Helper           []byte `json:"helper,omitempty"`
}

// Walk the finite payload schema once for metadata, hashing, transfer and budget
// accounting. The callback cannot add an executable or destination.
func (h *HostRecoveryBootstrap) payloads(fn func(string, *[]byte, uint64) error) error {
	if h == nil {
		return nil
	}
	if err := fn(h.BinarySHA256, &h.Binary, 96<<20); err != nil {
		return err
	}
	if err := fn(h.ProfileSHA256, &h.Profile, 256<<10); err != nil {
		return err
	}
	for i := range h.MACHooks {
		m := &h.MACHooks[i]
		if err := fn(m.SourceHookSHA256, &m.SourceHook, 64<<10); err != nil {
			return err
		}
		if err := fn(m.HelperSHA256, &m.Helper, 64<<10); err != nil {
			return err
		}
	}
	return nil
}
func (h *HostRecoveryBootstrap) Validate(content bool) error {
	if h == nil {
		return nil
	}
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	if h.JournalLayout != "FleetHostV1" || h.ServiceSHA256 != Digest(host.RecoveryServiceUnit()) || h.TimerSHA256 != Digest(host.RecoveryTimerUnit()) || h.ConfigSHA256 != Digest(cfg) || len(h.MACHooks) > 2 {
		return fmt.Errorf("invalid fixed host bootstrap")
	}
	seen := map[string]bool{}
	for _, m := range h.MACHooks {
		if _, _, err := host.ImportedMACPaths(m.Kind); err != nil || seen[m.Kind] || m.HelperSHA256 != host.ImportedHelperSHA256(m.Kind) {
			return fmt.Errorf("unqualified imported MAC helper")
		}
		seen[m.Kind] = true
	}
	if err := h.payloads(func(hash string, data *[]byte, limit uint64) error {
		if !shaPattern.MatchString(hash) || uint64(len(*data)) > limit || (content && (len(*data) == 0 || Digest(*data) != hash)) {
			return fmt.Errorf("invalid host payload identity or size")
		}
		return nil
	}); err != nil {
		return err
	}
	if content {
		p, err := host.ValidateNativeProfile(h.Profile)
		if err != nil {
			return err
		}
		if len(p.LegacyMACHooks) != len(h.MACHooks) {
			return fmt.Errorf("profile/imported hook mismatch")
		}
		for _, m := range h.MACHooks {
			found := false
			for _, ph := range p.LegacyMACHooks {
				if ph.Kind == m.Kind && ph.HelperSHA256 == m.HelperSHA256 && ph.HookSHA256 == Digest(host.ImportedMACUnit(m.Kind)) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("profile does not bind effective imported hook")
			}
		}
	}
	return nil
}

// WithoutContent copies all metadata without mutating caller-owned payloads.
func (b Bundle) WithoutContent() Bundle {
	b.Files = append([]File(nil), b.Files...)
	for i := range b.Files {
		b.Files[i].Data = nil
	}
	if b.Bootstrap != nil {
		s := *b.Bootstrap
		b.Bootstrap = &s
		s.Supervisor = nil
		s.Policy = nil
		if s.HostRecovery != nil {
			h := *s.HostRecovery
			s.HostRecovery = &h
			h.MACHooks = append([]MACHookBootstrap(nil), h.MACHooks...)
			_ = h.payloads(func(_ string, p *[]byte, _ uint64) error { *p = nil; return nil })
		}
	}
	return b
}

func (b Bundle) BootstrapContent() map[string][]byte {
	out := map[string][]byte{}
	if b.Bootstrap != nil {
		out[b.Bootstrap.SupervisorSHA256] = b.Bootstrap.Supervisor
		out[b.Bootstrap.PolicySHA256] = b.Bootstrap.Policy
		_ = b.Bootstrap.HostRecovery.payloads(func(hash string, p *[]byte, _ uint64) error { out[hash] = *p; return nil })
	}
	return out
}
