// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type routingRelayReceipt struct {
	Pending       bool   `json:"pending,omitempty"`
	DBHash        string `json:"relayConfigHash"` // Relevant relay inputs, not the full transaction DB.
	Container     string `json:"container"`
	GeneratedHash string `json:"generatedHash"`
	ProcessHash   string `json:"processHash"`
}

// Hash the shared relay service's configuration inputs. All VLAN/interface
// addressing is relevant to generated upstream lists; unrelated routing state,
// unused VRFs, and BGP policy are not. Unknown relay fields remain included.
func routingRelayConfigHash(db vlanChangeDB) string {
	relevant := vlanChangeDB{}
	vrfs := map[string]bool{}
	for key, fields := range db {
		table, _, _ := strings.Cut(key, "|")
		switch table {
		case "DHCP_RELAY", "DHCPV4_RELAY", "VLAN", "VLAN_MEMBER", "VLAN_INTERFACE", "INTERFACE", "PORTCHANNEL_INTERFACE", "LOOPBACK_INTERFACE", "DHCP_SERVER_IPV4", "DPUS", "MID_PLANE_BRIDGE":
			relevant[key] = fields
			if vrf := fields["vrf_name"]; vrf != "" {
				vrfs[vrf] = true
			}
			if vrf := fields["server_vrf"]; vrf != "" {
				vrfs[vrf] = true
			}
		case "PORT", "PORTCHANNEL":
			if alias, ok := fields["alias"]; ok {
				relevant[key] = map[string]string{"alias": alias}
			}
		}
	}
	metadata := map[string]string{}
	for _, field := range []string{"has_sonic_dhcpv4_relay", "subtype", "deployment_id", "hostname", "mac"} {
		if value, ok := db["DEVICE_METADATA|localhost"][field]; ok {
			metadata[field] = value
		}
	}
	relevant["DEVICE_METADATA|localhost"] = metadata
	for _, name := range []string{"dhcp_server", "dhcp_relay"} {
		if fields, ok := db["FEATURE|"+name]; ok {
			relevant["FEATURE|"+name] = fields
		}
	}
	for vrf := range vrfs {
		if fields, ok := db["VRF|"+vrf]; ok {
			relevant["VRF|"+vrf] = fields
		}
	}
	return vlanAuthorityHash(relevant)
}

func routingRelayValidateStorage(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if err := vlanAuthoritySecure(info, true); err != nil {
		return err
	}
	if info.Mode().Perm()&0700 != 0700 {
		return fmt.Errorf("relay receipt directory requires owner read/write/search permissions")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "launch.json" && entry.Name() != "launch.json.tmp" {
			return fmt.Errorf("unrecognized relay receipt storage entry")
		}
		f, err := root.OpenFile(entry.Name(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err == nil {
			err = vlanAuthoritySecure(info, false)
		}
		if err == nil && info.Mode().Perm()&0600 != 0600 {
			err = fmt.Errorf("relay receipt requires owner read/write permissions")
		}
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	if _, err := routingRelayReceiptFile(filepath.Dir(dir), nil); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Called only by Ensure's Preflight under the network lock, before any pending
// record or CAS. Probe actual write/fsync/rename capability, not just mode bits;
// this detects read-only mounts/ProtectSystem without replacing launch evidence.
func routingRelayPrepareStorage(journal string) error {
	if journal == "" {
		return fmt.Errorf("network journal required")
	}
	dir := filepath.Join(journal, "relay-runtime")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := routingRelayValidateStorage(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	// Reuse the recognized temporary filename, but refuse an existing file: a
	// previous interrupted receipt write requires inspection, not silent erasure.
	f, err := root.OpenFile("launch.json.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove("launch.json.tmp") }()
	_, err = f.Write([]byte("receipt storage preflight\n"))
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
	// Renaming a file to itself does not exercise the directory's rename path.
	const probe = ".receipt-preflight"
	if err := root.Rename("launch.json.tmp", probe); err != nil {
		return err
	}
	defer func() { _ = root.Remove(probe) }()
	if err := root.Remove(probe); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return err
	}
	parent, err := os.Open(journal)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return parent.Sync()
}

type routingRelayOps struct {
	read     routingRead
	snapshot func(context.Context) (vlanChangeDB, error)
	restart  func(context.Context) error
	load     func() (routingRelayReceipt, error)
	store    func(routingRelayReceipt) error
	wait     func(context.Context) error
}

func routingRelayOperations(m *SonicAgent) routingRelayOps {
	return routingRelayOps{
		read: runRoutingRead,
		snapshot: func(ctx context.Context) (vlanChangeDB, error) {
			db, _, err := m.vlanChangeSnapshot(ctx)
			return db, err
		},
		restart: func(ctx context.Context) error {
			return restartRoutingRelay(ctx, func(cmd *exec.Cmd) error { return cmd.Run() })
		},
		load: func() (routingRelayReceipt, error) { return routingRelayReceiptFile(m.networkJournalDir, nil) },
		store: func(r routingRelayReceipt) error {
			_, err := routingRelayReceiptFile(m.networkJournalDir, &r)
			return err
		},
		wait: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				return nil
			}
		},
	}
}

// Only the shared writer invokes Activate, after durable intent and CONFIG_DB
// CAS. Get/Runtime never call this function. No caller input reaches argv.
func restartRoutingRelay(ctx context.Context, run func(*exec.Cmd) error) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "dhcp_relay.service")
	cmd.WaitDelay = time.Second
	if fixture, ok := ctx.Value(routingCommandRunnerKey{}).(routingCommandRunner); ok {
		_, err := fixture(cmd)
		return err
	}
	if err := run(cmd); err != nil {
		return fmt.Errorf("DHCP relay restart failed or outcome uncertain: %w", err)
	}
	return nil
}

// A recognized private subdirectory keeps runtime receipts separate from the engine's
// strictly allowlisted journal files. Receipts are evidence only, never authority
// to mutate. The network writer lock serializes all receipt writes.
func routingRelayReceiptFile(journal string, write *routingRelayReceipt) (routingRelayReceipt, error) {
	var receipt routingRelayReceipt
	if journal == "" {
		return receipt, fmt.Errorf("network journal required for relay launch evidence")
	}
	dir := filepath.Join(journal, "relay-runtime")
	if write != nil {
		if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return receipt, err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return receipt, err
	}
	if err := vlanAuthoritySecure(info, true); err != nil {
		return receipt, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return receipt, err
	}
	defer func() { _ = root.Close() }()
	if write == nil {
		f, err := root.OpenFile("launch.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return receipt, err
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return receipt, err
		}
		if err := vlanAuthoritySecure(info, false); err != nil {
			return receipt, err
		}
		d := json.NewDecoder(io.LimitReader(f, 4096))
		d.DisallowUnknownFields()
		if err := d.Decode(&receipt); err != nil {
			return receipt, err
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return receipt, fmt.Errorf("invalid relay receipt")
		}
		return receipt, nil
	}
	if err := root.Remove("launch.json.tmp"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return receipt, err
	}
	f, err := root.OpenFile("launch.json.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return receipt, err
	}
	err = json.NewEncoder(f).Encode(write)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	if err := root.Rename("launch.json.tmp", "launch.json"); err != nil {
		return receipt, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return receipt, err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return receipt, err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return receipt, err
	}
	defer func() { _ = parent.Close() }()
	if err := parent.Sync(); err != nil {
		return receipt, err
	}
	return *write, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func routingRelayEvidence(ctx context.Context, ops routingRelayOps, desired vlanChangeDB, vlan string, native bool, v4, v6 []string) (routingRelayReceipt, bool, error) {
	var evidence routingRelayReceipt
	db, err := ops.snapshot(ctx)
	if err != nil {
		return evidence, false, err
	}
	if !networkSubset(db, desired) {
		return evidence, false, nil
	}
	evidence.DBHash = routingRelayConfigHash(db)
	identity, err := ops.read(ctx, routingRelayContainer)
	if err != nil {
		return evidence, false, err
	}
	var containers []struct {
		ID    string `json:"Id"`
		State struct {
			Running   bool   `json:"Running"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if json.Unmarshal(identity, &containers) != nil || len(containers) != 1 || containers[0].ID == "" || containers[0].State.StartedAt == "" {
		return evidence, false, fmt.Errorf("invalid relay container identity")
	}
	evidence.Container = containers[0].ID + "/" + containers[0].State.StartedAt
	if !containers[0].State.Running {
		return evidence, false, nil
	}
	generated, err := ops.read(ctx, routingRelayGenerated)
	if err != nil {
		return evidence, false, err
	}
	expected, err := ops.read(ctx, routingRelayRendered)
	if err != nil {
		return evidence, false, err
	}
	if string(generated) != string(expected) {
		return evidence, false, nil
	}
	evidence.GeneratedHash = vlanChangeHash(generated)
	processes, err := ops.read(ctx, routingRelayProcessIdentity)
	if err != nil {
		return evidence, false, err
	}
	var procs []struct {
		PID   string   `json:"pid"`
		Start string   `json:"start"`
		Args  []string `json:"argv"`
	}
	if json.Unmarshal(processes, &procs) != nil {
		return evidence, false, fmt.Errorf("invalid relay process identity")
	}
	v6Running, v4Running := false, false
	var args []string
	for _, p := range procs {
		if p.PID == "" || p.Start == "" || len(p.Args) == 0 {
			return evidence, false, fmt.Errorf("incomplete relay process identity")
		}
		if p.Args[0] == "/usr/sbin/dhcp6relay" {
			v6Running = true
		}
		if p.Args[0] == "/usr/sbin/dhcp4relay" {
			v4Running = true
		}
		args = append(args, strings.Join(p.Args, " "))
	}
	evidence.ProcessHash = vlanChangeHash(processes)
	readProcess := func(_ context.Context, c routingReadCommand) ([]byte, error) {
		return []byte(strings.Join(args, "\n")), nil
	}
	legacyVerified, _, err := observeRoutingRelay(ctx, readProcess, vlan, native, v4, nil)
	if err != nil {
		return evidence, false, err
	}
	if len(v4) > 0 && !native && !legacyVerified {
		return evidence, false, nil
	}
	if len(v4) > 0 && native && !v4Running {
		return evidence, false, nil
	}
	if len(v6) > 0 && (!v6Running || !strings.Contains(string(generated), "[program:dhcp6relay]\ncommand=/usr/sbin/dhcp6relay\n")) {
		return evidence, false, nil
	}
	after, err := ops.snapshot(ctx)
	if err != nil {
		return evidence, false, err
	}
	if routingRelayConfigHash(after) != evidence.DBHash {
		return evidence, false, nil
	}
	endIdentity, err := ops.read(ctx, routingRelayContainer)
	if err != nil {
		return evidence, false, err
	}
	var end []struct {
		ID    string `json:"Id"`
		State struct {
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if json.Unmarshal(endIdentity, &end) != nil || len(end) != 1 || end[0].ID+"/"+end[0].State.StartedAt != evidence.Container {
		return evidence, false, nil
	}
	return evidence, true, nil
}

func activateRoutingRelay(ctx context.Context, ops routingRelayOps, desired vlanChangeDB, vlan string, native bool, v4, v6 []string) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	// A durable matching receipt avoids replaying a restart after a later save
	// failure. The engine never re-dispatches an uncertain activation; recovery
	// observes the pending launch receipt without invoking this callback again.
	before, ready, _ := routingRelayEvidence(ctx, ops, desired, vlan, native, v4, v6)
	if receipt, err := ops.load(); err == nil && ready && receipt == before {
		return nil
	}
	db, err := ops.snapshot(ctx)
	if err != nil {
		return err
	}
	if !networkSubset(db, desired) {
		return fmt.Errorf("relay activation requires exact intended CONFIG_DB fields")
	}
	hash := vlanAuthorityHash(db)
	// Record the pre-launch binding before dispatch. If the restart succeeds but
	// its RPC times out or the agent exits, read-only recovery can prove a fresh
	// container against this expected DB without replaying the service restart.
	if before.Container == "" {
		return fmt.Errorf("cannot establish pre-restart relay container identity")
	}
	if err := ops.store(routingRelayReceipt{Pending: true, DBHash: routingRelayConfigHash(db), Container: before.Container}); err != nil {
		return err
	}
	// Dispatch only after recording the expected DB and old container identity.
	if err := ops.restart(ctx); err != nil {
		return err
	}
	for attempt := 0; attempt < 30; attempt++ {
		evidence, ready, err := routingRelayEvidence(ctx, ops, desired, vlan, native, v4, v6)
		current, snapshotErr := ops.snapshot(ctx)
		if snapshotErr != nil {
			return snapshotErr
		}
		if vlanAuthorityHash(current) != hash {
			return fmt.Errorf("CONFIG_DB changed during relay activation")
		}
		if err == nil && ready && evidence.DBHash == routingRelayConfigHash(db) && evidence.Container != before.Container {
			if err := ops.store(evidence); err != nil {
				return fmt.Errorf("relay launch receipt durability uncertain: %w", err)
			}
			return nil
		}
		if err := ops.wait(ctx); err != nil {
			return err
		}
	}
	return fmt.Errorf("relay restart acknowledged but generated configuration/fresh process launch not verified; activation remains pending")
}

func routingRelayRuntime(ctx context.Context, ops routingRelayOps, desired vlanChangeDB, vlan string, native bool, v4, v6 []string) (bool, json.RawMessage, error) {
	if len(v6) == 0 {
		return observeRoutingRelay(ctx, ops.read, vlan, native, v4, v6)
	}
	evidence, ready, err := routingRelayEvidence(ctx, ops, desired, vlan, native, v4, v6)
	if err != nil {
		return false, nil, err
	}
	receipt, loadErr := ops.load()
	bound := loadErr == nil && ready && (evidence == receipt || (receipt.Pending && receipt.DBHash == evidence.DBHash && receipt.Container != "" && receipt.Container != evidence.Container))
	observed, _ := json.Marshal(map[string]any{"vlan": vlan, "startupConfigVerified": bound, "ipv6ConfigVerified": bound, "nativeIPv4AppliedConfigVerified": false, "forwardingTested": false, "message": "IPv6 verification binds a journaled restart and fresh daemon launch to unchanged relay configuration/dependencies and regenerated supervisor config; no lease/packet-forwarding claim"})
	return bound, observed, nil
}
