// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed package_transaction.py
var packageTransactionScript string

type packageEntry struct {
	Data []byte `json:"data"`
	Mode uint32 `json:"mode"`
}
type packageSnapshot struct {
	Version int                     `json:"version"`
	Entries map[string]packageEntry `json:"entries"`
}
type packageRecovery struct {
	Target    string `json:"target"`
	Before    string `json:"before"`
	Candidate string `json:"candidate"`
	Observed  string `json:"observed,omitempty"`
}

func packageGeneratedSlot(j *journal, slot string) bool {
	has := false
	for _, f := range j.Files {
		has = has || f.Slot == "PlatformWheel"
	}
	if !has {
		return false
	}
	_, module := platformModules[slot]
	return module
}

func candidatePackage(members map[string][]byte, wheelHash, target string) packageSnapshot {
	s := packageSnapshot{Version: 1, Entries: map[string]packageEntry{}}
	for name, data := range members {
		if strings.HasSuffix(name, "/RECORD") {
			continue
		}
		s.Entries[name] = packageEntry{Data: data, Mode: 0644}
	}
	prefix := "sonic_platform-1.0.dist-info/"
	s.Entries[prefix+"INSTALLER"] = packageEntry{Data: []byte("sonic-operator\n"), Mode: 0644}
	s.Entries[prefix+"REQUESTED"] = packageEntry{Data: []byte{}, Mode: 0644}
	receipt, _ := json.Marshal(map[string]any{"archive_info": map[string]any{"hashes": map[string]string{"sha256": wheelHash}}, "url": "file://" + coreWheel})
	s.Entries[prefix+"direct_url.json"] = packageEntry{Data: receipt, Mode: 0644}
	names := make([]string, 0, len(s.Entries))
	for name := range s.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var record bytes.Buffer
	writer := csv.NewWriter(&record)
	for _, name := range names {
		entry := s.Entries[name]
		writer.Write([]string{name, "sha256=" + wheelHashBase64(entry.Data), strconv.Itoa(len(entry.Data))})
	}
	writer.Write([]string{prefix + "RECORD", "", ""})
	writer.Flush()
	s.Entries[prefix+"RECORD"] = packageEntry{Data: record.Bytes(), Mode: 0644}
	return s
}
func validateBeforePackage(s packageSnapshot, members map[string][]byte) error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported package snapshot")
	}
	for name, data := range members {
		if strings.HasSuffix(name, "/RECORD") {
			continue
		}
		entry, ok := s.Entries[name]
		if !ok || !bytes.Equal(entry.Data, data) {
			return fmt.Errorf("before package does not match protected before wheel")
		}
	}
	if _, ok := s.Entries["sonic_platform-1.0.dist-info/RECORD"]; !ok {
		return fmt.Errorf("unowned before package lacks metadata authority")
	}
	return nil
}
func (n *Native) packageCommand(ctx context.Context, target string, input []byte) ([]byte, error) {
	args := []string{"-I", "-B", "-c", packageTransactionScript + "\nmain()"}
	command := "/usr/bin/python3"
	if target == "pmon" {
		command = "/usr/bin/docker"
		args = append([]string{"exec", "-i", "pmon", "/usr/bin/timeout", "--signal=KILL", "30s", "python3"}, args...)
	} else if target == "host" {
		command = "/usr/bin/timeout"
		args = append([]string{"--signal=KILL", "30s", "/usr/bin/python3"}, args...)
	} else {
		return nil, fmt.Errorf("unqualified package target")
	}
	if n.RunInput != nil {
		return n.RunInput(ctx, input, command, args...)
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bounded package transaction failed")
	}
	if len(out) > 48<<20 {
		return nil, fmt.Errorf("package snapshot response too large")
	}
	return out, nil
}
func (n *Native) preparePackages(ctx context.Context, j *journal) error {
	if j.PackagesPrepared || (j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot") && len(j.Packages) > 0 {
		return nil
	}
	e := n.Engine
	var wheel *savedFile
	index := 0
	for i := range j.Files {
		if j.Files[i].Slot == "PlatformWheel" {
			wheel = &j.Files[i]
			index = i
			break
		}
	}
	if wheel == nil {
		return nil
	}
	old, _, err := e.read(e.storage(j, "old", index))
	if err != nil || Digest(old) != wheel.PreviousHash {
		return fmt.Errorf("protected before wheel unavailable")
	}
	beforeMembers, err := wheelMembers(old)
	if err != nil {
		return err
	}
	data, _, err := e.read(e.storage(j, "new", index))
	if err != nil || Digest(data) != wheel.Hash {
		return fmt.Errorf("candidate wheel unavailable")
	}
	candidateMembers, err := wheelMembers(data)
	if err != nil {
		return err
	}
	records := make([]packageRecovery, 0, 2)
	for _, target := range []string{"host", "pmon"} {
		packet, _ := json.Marshal(map[string]any{"target": target, "token": j.Token, "mode": "snapshot"})
		raw, err := n.packageCommand(ctx, target, packet)
		if err != nil {
			return err
		}
		var observed packageSnapshot
		if Decode(raw, &observed) != nil {
			return fmt.Errorf("invalid package snapshot response")
		}
		var before packageSnapshot
		// Keep owned recovery state distinct from the bytes currently observed.
		for _, inherited := range j.Packages {
			if inherited.Target == target {
				beforeRaw, err := e.readPackagePayload(j, inherited, "before")
				if err != nil {
					return err
				}
				if Decode(beforeRaw, &before) != nil {
					return fmt.Errorf("invalid inherited package authority")
				}
				break
			}
		}
		if before.Entries == nil {
			before = observed
		}
		if err := validateBeforePackage(before, beforeMembers); err != nil {
			return err
		}
		candidate := candidatePackage(candidateMembers, wheel.Hash, target)
		if err := validateObservedPackage(observed, before, candidate); err != nil {
			return err
		}
		beforeRaw, _ := json.Marshal(before)
		candidateRaw, _ := json.Marshal(candidate)
		observedRaw, _ := json.Marshal(observed)
		entry := packageRecovery{Target: target, Before: Digest(beforeRaw), Candidate: Digest(candidateRaw), Observed: Digest(observedRaw)}
		if err := e.atomic(e.packagePath(j, target, "before", entry.Before), beforeRaw, 0600); err != nil {
			return err
		}
		if err := e.atomic(e.packagePath(j, target, "candidate", entry.Candidate), candidateRaw, 0600); err != nil {
			return err
		}
		if err := e.atomic(e.packagePath(j, target, "observed", entry.Observed), observedRaw, 0600); err != nil {
			return err
		}
		records = append(records, entry)
	}
	j.Packages = records
	j.PackagesPrepared = true
	// Both targets' validated repair authority precedes either package mutation.
	if err := e.save(j); err != nil {
		return err
	}
	return nil
}
func (e *Engine) packagePath(j *journal, target, which string, hash ...string) string {
	name := target + "-" + which
	if len(hash) > 0 {
		name += "-" + hash[0]
	}
	return path.Join(e.state, j.Token, "package", name+".json")
}
func (n *Native) applyPackages(ctx context.Context, j *journal, restore bool) error {
	if !restore {
		if err := n.preparePackages(ctx, j); err != nil {
			return err
		}
	}
	if len(j.Packages) > 0 {
		if err := n.stopPackageConsumers(ctx); err != nil {
			return err
		}
	}
	for _, entry := range j.Packages {
		if entry.Target != "host" && entry.Target != "pmon" {
			return fmt.Errorf("unqualified package recovery target")
		}
		beforeRaw, err := n.Engine.readPackagePayload(j, entry, "before")
		if err != nil {
			return fmt.Errorf("package before snapshot lost")
		}
		candidateRaw, err := n.Engine.readPackagePayload(j, entry, "candidate")
		if err != nil {
			return fmt.Errorf("package candidate authority lost")
		}
		var before, candidate packageSnapshot
		if Decode(beforeRaw, &before) != nil || Decode(candidateRaw, &candidate) != nil {
			return fmt.Errorf("invalid protected package snapshots")
		}
		var observed packageSnapshot
		if entry.Observed != "" {
			raw, err := n.Engine.readPackagePayload(j, entry, "observed")
			if err != nil {
				return err
			}
			if Decode(raw, &observed) != nil {
				return fmt.Errorf("invalid package CAS observation")
			}
		}
		if entry.Observed == "" {
			observed = before
		}
		mode := "apply"
		if restore {
			mode = "restore"
		}
		if !restore && (j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot") {
			mode = "enforce"
		}
		packet, _ := json.Marshal(map[string]any{"target": entry.Target, "token": j.Token, "mode": mode, "before": before, "candidate": candidate, "observed": observed})
		if _, err := n.packageCommand(ctx, entry.Target, packet); err != nil {
			return err
		}
	}
	return nil
}
func (n *Native) stopPackageConsumers(ctx context.Context) error {
	for _, name := range []string{"xcvrd", "psud", "syseepromd", "stormond"} {
		raw, err := n.command(ctx, "/usr/bin/docker", "exec", "pmon", "supervisorctl", "pid", name)
		if err != nil {
			return ErrActivationPending
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			return fmt.Errorf("invalid package consumer process identity")
		}
		if pid > 0 {
			if _, err := n.command(ctx, "/usr/bin/docker", "exec", "pmon", "supervisorctl", "stop", name); err != nil {
				return err
			}
		}
	}
	return nil
}
func (n *Native) RestorePackages() error {
	j, err := n.Engine.load()
	if err != nil || j == nil || len(j.Packages) == 0 || !platformMutation(j) {
		return err
	}
	ctx, cancel := n.activationContext(j)
	defer cancel()
	if !n.containerRunning(ctx, "pmon") {
		_, err := n.command(ctx, "/usr/bin/systemctl", "--no-block", "start", "pmon.service")
		if err != nil {
			return err
		}
		return ErrActivationPending
	}
	if err := n.consumersReady(ctx, true); err != nil {
		return err
	}
	return n.applyPackages(ctx, j, true)
}
func (n *Native) RestoreBootRuntime() error {
	j, err := n.Engine.load()
	if err != nil || j == nil || j.Active == nil {
		return err
	}
	ctx, cancel := n.activationContext(j)
	defer cancel()
	if len(j.Active.Packages) == 0 {
		return n.Engine.Health()
	}
	if j.BootRuntimeApplied {
		identity, err := n.bootRuntimeIdentity(ctx)
		if err != nil {
			return err
		}
		if identity == j.BootRuntimeIdentity {
			return n.Engine.Health()
		}
		j.BootRuntimeApplied = false
		j.BootRuntimeIdentity = ""
		if err := n.Engine.save(j); err != nil {
			return err
		}
	}
	if err := n.consumersReady(ctx, false); err != nil {
		return err
	}
	if err := n.consumerBaseline(ctx); err != nil {
		return err
	}
	source := *j
	source.Token = j.Active.Token
	source.Files = j.Active.Files
	source.Packages = j.Active.Packages
	if len(source.Packages) > 0 {
		if err := n.applyPackages(ctx, &source, false); err != nil {
			return err
		}
		if err := n.configureLaunchersFrom(ctx, j, &source, false); err != nil {
			return err
		}
	}
	identity, err := n.qualifiedBootRuntimeIdentity(ctx, j)
	if err != nil {
		return err
	}
	j.BootRuntimeApplied = true
	j.BootRuntimeIdentity = identity
	if err := n.Engine.save(j); err != nil {
		return err
	}
	return n.Engine.Health()
}
