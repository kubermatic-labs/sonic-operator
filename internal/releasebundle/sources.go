// SPDX-License-Identifier: Apache-2.0
package releasebundle

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

type HookInput struct {
	Declaration       host.LegacyMACHook `json:"declaration"`
	InterpreterSHA256 string             `json:"interpreterSHA256"`
	HelperFile        string             `json:"helperFile"`
	SourceHookFile    string             `json:"sourceHookFile"`
	SourceHookSHA256  string             `json:"sourceHookSHA256"`
}
type SwitchInput struct {
	ImportedMACEnvironment string                `json:"importedMACEnvironment,omitempty"`
	Switch                 string                `json:"switch"`
	Agent                  artifact.AgentOptions `json:"agent"`
	Hooks                  []HookInput           `json:"hooks"`
}
type Sources struct {
	HostRecovery        *artifact.HostRecoveryBootstrap `json:"hostRecovery"`
	Format              string                          `json:"format"`
	ReleaseSHA256       string                          `json:"releaseSHA256"`
	Switch              string                          `json:"switch,omitempty"`
	Coverage            string                          `json:"coverage"`
	Baseline            string                          `json:"baseline"`
	Sources             map[string]Source               `json:"sources"`
	GeneratedSHA256     map[string]string               `json:"generatedSHA256"`
	PublicBytes         int64                           `json:"publicBytes"`
	PrivateReserveBytes int64                           `json:"privateReserveBytes"`
	AdditionalBytes     int64                           `json:"additionalBytes"`
}

// BuildSources finishes all validation and sizing before its caller writes any
// output. Returned ConfigMaps deliberately have no UID; publication is separate.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func BuildSources(repo string, releaseRaw []byte, paths map[string]string, profileRaw []byte, baseline string, input *SwitchInput, additional int64) (Sources, []ConfigMap, error) {
	s := Sources{Format: "host-artifact-sources-v1", ReleaseSHA256: artifact.Digest(releaseRaw), Coverage: "unverified: source-only; native installation, timers, boot and forwarding are not verified", Baseline: baseline, Sources: map[string]Source{}, GeneratedSHA256: map[string]string{}, PrivateReserveBytes: 3 * (64 << 10), AdditionalBytes: additional}
	var r Release
	if artifact.Decode(releaseRaw, &r) != nil || ValidateRelease(r) != nil {
		return s, nil, fmt.Errorf("invalid release input")
	}
	if baseline == "" || len(baseline) > 128 || additional < 0 {
		return s, nil, fmt.Errorf("explicit bounded baseline and extra-public byte count required")
	}
	for _, b := range r.Builds {
		if CheckAncestry(repo, b.Info) != nil {
			return s, nil, fmt.Errorf("candidate below source floor")
		}
	}
	for _, b := range r.Fallbacks {
		if CheckAncestry(repo, b.Info) != nil {
			return s, nil, fmt.Errorf("fallback below source floor")
		}
	}
	p, err := host.ValidateNativeProfile(profileRaw)
	if err != nil || len(p.LegacyMACHooks) != 0 {
		return s, nil, fmt.Errorf("measured base profile required; imports must be explicit")
	}
	payloads := map[string][]byte{}
	for role, slot := range map[string]string{"agent": "AgentBinary", "supervisor": "SupervisorBinary", "watchdog": "HostRecoveryBinary"} {
		b, payload, err := readInspectedBinary(repo, paths[role], role)
		if err != nil || b.SHA256 != r.Builds[role].SHA256 || !releaseinfo.Equal(b.Info, r.Builds[role].Info) || b.Size != r.Builds[role].Size {
			return s, nil, fmt.Errorf("built source differs from release")
		}
		payloads[slot] = payload
	}
	if input != nil {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`).MatchString(input.Switch) || len(input.Hooks) > 1 || !input.Agent.HostGuard || !input.Agent.Artifacts || input.Agent.ReadOnly {
			return s, nil, fmt.Errorf("unqualified switch source input")
		}
		s.Switch = input.Switch
		unit, err := artifact.AgentUnit(input.Agent)
		if err != nil {
			return s, nil, err
		}
		s.GeneratedSHA256["AgentUnit"] = artifact.Digest(unit)
		for _, h := range input.Hooks {
			decl := h.Declaration
			if decl.HelperSHA256 != host.ImportedHelperSHA256(decl.Kind) || !hashPattern.MatchString(h.InterpreterSHA256) || decl.HookSHA256 != artifact.Digest(host.ImportedMACUnit(decl.Kind)) || !hashPattern.MatchString(h.SourceHookSHA256) {
				return s, nil, fmt.Errorf("unqualified explicit hook identity")
			}
			helper, err := ReadBounded(h.HelperFile, 64<<10)
			if err != nil || artifact.Digest(helper) != decl.HelperSHA256 {
				return s, nil, fmt.Errorf("import helper differs from reviewed bytes")
			}
			hook, err := ReadBounded(h.SourceHookFile, 64<<10)
			if err != nil || artifact.Digest(hook) != h.SourceHookSHA256 || !publicHook(hook) {
				return s, nil, fmt.Errorf("source hook is not bounded public unit metadata")
			}
			p.LegacyMACHooks = append(p.LegacyMACHooks, decl)
			key := "imported-shell"
			if host.IsImportedPythonKind(decl.Kind) {
				key = "imported-python"
			}
			p.ConsumerSHA256[key] = h.InterpreterSHA256
			payloads["ImportedHelper"] = helper
			payloads["ImportedHook"] = hook
			s.GeneratedSHA256["ImportedMACUnit"] = artifact.Digest(host.ImportedMACUnit(decl.Kind))
		}
		if err := sourceImportedEnvironment(&p, input.ImportedMACEnvironment, r); err != nil {
			return s, nil, err
		}
		profileRaw, err = JSON(p)
		if err != nil {
			return s, nil, err
		}
		if _, err = host.ValidateNativeProfile(profileRaw); err != nil {
			return s, nil, fmt.Errorf("explicit imported profile does not qualify")
		}
	}
	payloads["HostProfile"] = profileRaw
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	s.HostRecovery = &artifact.HostRecoveryBootstrap{BinarySHA256: r.Builds["watchdog"].SHA256, ProfileSHA256: artifact.Digest(profileRaw), ServiceSHA256: artifact.Digest(host.RecoveryServiceUnit()), TimerSHA256: artifact.Digest(host.RecoveryTimerUnit()), ConfigSHA256: artifact.Digest(cfg), JournalLayout: "FleetHostV1"}
	if input != nil {
		for _, h := range input.Hooks {
			s.HostRecovery.MACHooks = append(s.HostRecovery.MACHooks, artifact.MACHookBootstrap{Kind: h.Declaration.Kind, HelperSHA256: h.Declaration.HelperSHA256, SourceHookSHA256: h.SourceHookSHA256})
		}
	}
	if err := s.HostRecovery.Validate(false); err != nil {
		return s, nil, err
	}
	policy := artifact.Policy{Baseline: baseline, ImageSHA256: p.ImageSHA256, AgentBuilds: r.AgentBuilds}
	payloads["Policy"], err = JSON(policy)
	if err != nil {
		return s, nil, err
	}
	for name, raw := range map[string][]byte{"HostConfig": cfg, "HostService": host.RecoveryServiceUnit(), "HostTimer": host.RecoveryTimerUnit(), "SupervisorUnit": []byte(artifact.SupervisorUnit)} {
		s.GeneratedSHA256[name] = artifact.Digest(raw)
	}
	sizes := []int64{s.PrivateReserveBytes, additional}
	for _, data := range payloads {
		sizes = append(sizes, int64(len(data)))
		s.PublicBytes += int64(len(data))
	}
	if err := CheckAggregate(sizes); err != nil {
		return s, nil, err
	}
	var objects []ConfigMap
	// Fixed order ensures reproducible ConfigMap files and chunk references.
	for _, slot := range []string{"AgentBinary", "SupervisorBinary", "HostRecoveryBinary", "Policy", "HostProfile", "ImportedHelper", "ImportedHook"} {
		data, ok := payloads[slot]
		if !ok {
			continue
		}
		ref, cms, err := ChunkSource(slot, data)
		if err != nil {
			return s, nil, err
		}
		s.Sources[slot] = ref
		objects = append(objects, cms...)
	}
	return s, objects, nil
}

func sourceImportedEnvironment(p *host.NativeProfile, recipe string, r Release) error {
	if recipe == "" {
		return nil
	}
	if recipe != host.ImportedMACEnvironmentNone || len(p.LegacyMACHooks) != 1 {
		return fmt.Errorf("explicit native environment requires one imported hook and a known recipe")
	}
	for _, b := range r.Builds {
		if !releaseinfo.SupportsImportedMACUnit(b.Info) {
			return fmt.Errorf("release lacks imported native unit reader")
		}
	}
	for _, b := range r.AgentBuilds {
		if !releaseinfo.SupportsImportedMACUnit(b) {
			return fmt.Errorf("accepted fallback lacks imported native unit reader")
		}
	}
	p.ImportedMACEnvironment = recipe
	return nil
}

// Imported source units contain only the captured fixed activation commands;
// environment variables, arbitrary values and credential-bearing directives are
// not public source inputs. The original hook is preserved, never executed here.
func publicHook(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "[Service]" {
			continue
		}
		switch line {
		case "ExecStartPost=/usr/local/sbin/set-management-mac", "ExecStartPost=/usr/bin/python3 /usr/local/sbin/dc-management-only-mac.py boot":
		default:
			return false
		}
	}
	return len(raw) > 0
}
