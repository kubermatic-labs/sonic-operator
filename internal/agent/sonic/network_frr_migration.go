// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

const frrMigrationIdentity = "FRRMigration|unified"

type frrMigrationSpec struct {
	routingSpecMeta
	Mode           string `json:"mode"`
	ApprovedDigest string `json:"approvedDigest,omitempty"`
}

// Empty mode is the legacy forward receipt convention.
func frrMigrationMode(mode ...string) string {
	if len(mode) > 0 && mode[0] != "" {
		return mode[0]
	}
	return "Unified"
}

func frrMigrationDesired(mode ...string) vlanChangeDB {
	if frrMigrationMode(mode...) == "Traditional" {
		return vlanChangeDB{"DEVICE_METADATA|localhost": {"frr_mgmt_framework_config": "false", "docker_routing_config_mode": "separated"}}
	}
	return vlanChangeDB{"DEVICE_METADATA|localhost": {"frr_mgmt_framework_config": "true", "docker_routing_config_mode": "unified"}}
}

func frrMigrationModeUpdate(key, field, before, after string) bool {
	if key != "DEVICE_METADATA|localhost" {
		return false
	}
	switch field {
	case "frr_mgmt_framework_config":
		return ((before == "" || before == "false") && after == "true") || (before == "true" && after == "false")
	case "docker_routing_config_mode":
		return ((before == "" || before == "separated") && after == "unified") || (before == "unified" && after == "separated")
	default:
		return false
	}
}

func planNetworkFRRMigration(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec frrMigrationSpec
	if err := routingDecode(r, "FRRMigration", &spec, "mode approvedDigest"); err != nil {
		return nil, err
	}
	if spec.Mode != "Unified" && spec.Mode != "Traditional" {
		return nil, fmt.Errorf("FRR migration supports Unified or Traditional")
	}
	if spec.ApprovedDigest != "" && !vlanAuthorityDigestValid(spec.ApprovedDigest) {
		return nil, fmt.Errorf("approvedDigest must be lowercase SHA256")
	}
	owner := r.OwnerID
	// Deliberately independent of current metadata. The original request must
	// recreate identical Desired and callbacks after CAS and agent restart.
	return &networkPlan{
		Identity: frrMigrationIdentity, Desired: frrMigrationDesired(spec.Mode),
		Preflight: func(ctx context.Context, m *SonicAgent) error {
			return frrMigrationPreflight(ctx, m, owner, spec.ApprovedDigest, spec.Mode)
		},
		Activate: func(ctx context.Context, m *SonicAgent) error { return activateFRRMigration(ctx, m, owner, spec.Mode) },
		Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
			return observeFRRMigration(ctx, m, owner, spec.Mode)
		},
	}, nil
}

func frrMigrationTraditional(db vlanChangeDB) bool {
	meta := db["DEVICE_METADATA|localhost"]
	return meta != nil && (meta["frr_mgmt_framework_config"] == "" || meta["frr_mgmt_framework_config"] == "false") && (meta["docker_routing_config_mode"] == "" || meta["docker_routing_config_mode"] == "separated")
}

// Fail closed on routing namespaces, including empty placeholder hashes. Layer-2
// ports/VLANs are allowed; any L3-interface row or unknown routing extension is not.
func frrMigrationEmptyDB(db vlanChangeDB) error {
	if db["DEVICE_METADATA|localhost"] == nil {
		return fmt.Errorf("missing device metadata")
	}
	for key, fields := range db {
		table, name, _ := strings.Cut(key, "|")
		if table == "BGP_DEVICE_GLOBAL" {
			if name != "STATE" || !reflect.DeepEqual(fields, map[string]string{"idf_isolation_state": "unisolated", "tsa_enabled": "false", "wcmp_enabled": "false"}) {
				return fmt.Errorf("unsupported BGP device defaults")
			}
			continue
		}
		for _, prefix := range []string{"BGP", "BFD", "OSPF", "ISIS", "PIM", "IGMP", "MROUTE", "STATIC_ROUTE", "VRF", "VNET", "VXLAN", "EVPN", "SRV6", "SEGMENT_ROUTING", "ROUTE", "PREFIX", "AS_PATH", "COMMUNITY", "EXTENDED_COMMUNITY", "REDISTRIBUTE", "POLICY", "TUNNEL", "INTERFACE", "LOOPBACK_INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_SUB_INTERFACE"} {
			if strings.HasPrefix(table, prefix) {
				return fmt.Errorf("routing configuration is not empty")
			}
		}
		if table == "DEVICE_METADATA" {
			if name != "localhost" {
				return fmt.Errorf("multiple routing namespaces unsupported")
			}
			for _, field := range []string{"bgp_asn", "type", "subtype", "peer_switch", "default_bgp_status", "deployment_id", "region", "cloudtype", "nexthop_group"} {
				value := fields[field]
				if value != "" && !(field == "default_bgp_status" && (value == "up" || value == "down")) {
					return fmt.Errorf("routing-generating device metadata unsupported")
				}
			}
		}
		if table == "MGMT_VRF_CONFIG" || table == "WARM_RESTART" {
			return fmt.Errorf("management VRF or warm restart unsupported")
		}
		if table == "SYSTEM_DEFAULTS" && name == "software_bfd" && fields["status"] != "disabled" {
			return fmt.Errorf("software BFD unsupported")
		}
	}
	return nil
}

func frrMigrationPost(db vlanChangeDB, mode ...string) vlanChangeDB {
	post := maps.Clone(db)
	meta := maps.Clone(db["DEVICE_METADATA|localhost"])
	if meta == nil {
		meta = map[string]string{}
	}
	maps.Copy(meta, frrMigrationDesired(mode...)["DEVICE_METADATA|localhost"])
	post["DEVICE_METADATA|localhost"] = meta
	return post
}

// Caller already holds the common network writer lock; never reacquire it.
func frrMigrationRecord(m *SonicAgent) (*networkRecord, error) {
	if m.networkJournalDir == "" {
		return nil, nil
	}
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return nil, fmt.Errorf("FRR migration journal unavailable")
	}
	defer root.Close()
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	if err != nil {
		return nil, fmt.Errorf("FRR migration journal invalid")
	}
	return state.Records[frrMigrationIdentity], nil
}

func frrMigrationTerminal(r *networkRecord, owner string, mode ...string) bool {
	return r != nil && r.OwnerID == owner && reflect.DeepEqual(r.Fields, frrMigrationDesired(mode...)) && (r.Pending == nil || (r.Pending.PreHash == r.Pending.PostHash && reflect.DeepEqual(r.Pending.After, frrMigrationDesired(mode...))))
}

func frrMigrationSource(db vlanChangeDB, mode string) bool {
	if mode == "Traditional" {
		return networkSubset(db, frrMigrationDesired())
	}
	return frrMigrationTraditional(db)
}

func frrMigrationPreflight(ctx context.Context, m *SonicAgent, owner, approval string, modes ...string) error {
	mode := frrMigrationMode(modes...)
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("FRR migration snapshot unavailable")
	}
	record, err := frrMigrationRecord(m)
	if err != nil {
		return err
	}
	if record != nil && record.OwnerID != owner {
		return fmt.Errorf("migration owned by another UID")
	}
	if frrMigrationTerminal(record, owner, mode) {
		if !networkSubset(db, frrMigrationDesired(mode)) {
			return fmt.Errorf("completed migration mode drifted")
		}
		return nil
	}
	if record != nil && record.Pending != nil && networkSubset(db, frrMigrationDesired(mode)) {
		receipt, err := frrMigrationPendingReceipt(m, owner, mode)
		p := record.Pending
		if err != nil || receipt.Owner != owner || receipt.Digest != approval || receipt.PreHash != p.PreHash || receipt.PostHash != p.PostHash || vlanAuthorityHash(db) != p.PostHash {
			return fmt.Errorf("migration preparation does not match pending transaction")
		}
		// Post-CAS recovery uses durable approval, not a newly generated digest.
		return frrMigrationCheckTarget(ctx, receipt)
	}
	if !vlanAuthorityDigestValid(approval) {
		return fmt.Errorf("explicit approvedDigest required for each mode transition")
	}
	if !frrMigrationSource(db, mode) {
		return fmt.Errorf("only supported opposite empty routing mode can be migrated; foreign target mode is not adopted")
	}
	if record != nil && !networkSubset(db, record.Fields) {
		return fmt.Errorf("owned migration mode drifted")
	}
	evidence, err := inspectFRRMigration(ctx, db, mode)
	if err != nil {
		return err
	}
	digest := frrMigrationDigest(db, evidence, mode)
	if digest != approval {
		return fmt.Errorf("FRR migration approval stale or mismatched")
	}
	latest, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil || vlanAuthorityHash(latest) != vlanAuthorityHash(db) {
		return fmt.Errorf("configuration changed during migration preflight")
	}
	if err := frrMigrationPrepareStorage(m.networkJournalDir); err != nil {
		return fmt.Errorf("FRR migration receipt storage unavailable")
	}
	before := networkTarget(db, frrMigrationDesired(mode))
	backupHash, err := frrMigrationBackup(m.networkJournalDir, evidence, before, digest)
	if err != nil {
		return fmt.Errorf("FRR migration backup unavailable or changed")
	}
	receipt := frrMigrationReceipt{Mode: mode, Owner: owner, Digest: digest, PreHash: vlanAuthorityHash(db), PostHash: vlanAuthorityHash(frrMigrationPost(db, mode)), Before: before, StartHash: evidence.StartHash, ConfigHash: evidence.ConfigHash, CandidateHash: evidence.CandidateHash, InputsHash: evidence.InputsHash, RoutesHash: evidence.RoutesHash, BackupHash: backupHash}
	receipt.ContainerHash = evidence.ContainerHash
	_, err = frrMigrationReceiptFile(m.networkJournalDir, &receipt)
	if err != nil {
		return fmt.Errorf("FRR migration preparation durability uncertain")
	}
	return nil
}

func observeFRRMigration(ctx context.Context, m *SonicAgent, owner string, modes ...string) (bool, json.RawMessage, error) {
	mode := frrMigrationMode(modes...)
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("FRR migration snapshot unavailable")
	}
	observed := map[string]any{"mode": mode, "preflightEligible": false, "adoptionDigest": "", "classification": "unsupported-or-nonempty", "forwardingTested": false}
	finish := func(ready bool, err error) (bool, json.RawMessage, error) {
		data, _ := json.Marshal(observed)
		return ready, data, err
	}
	record, err := frrMigrationRecord(m)
	if err != nil {
		return finish(false, err)
	}
	if frrMigrationTerminal(record, owner, mode) {
		ready, err := frrMigrationModeReady(ctx, mode)
		observed["classification"] = "migration-complete"
		return finish(ready && networkSubset(db, frrMigrationDesired(mode)), err)
	}
	if (record == nil || record.Pending == nil) && frrMigrationSource(db, mode) {
		evidence, err := inspectFRRMigration(ctx, db, mode)
		if err == nil {
			classification := "eligible-empty-traditional"
			if mode == "Traditional" {
				classification = "eligible-empty-unified"
			}
			observed["preflightEligible"], observed["adoptionDigest"], observed["classification"] = true, frrMigrationDigest(db, evidence, mode), classification
		} else {
			observed["preflightReason"] = frrMigrationReason(err)
		}
		// Ineligibility is an observation. Neither raw config nor command output
		// (including errors that may quote secrets) crosses the RPC boundary.
		return finish(false, nil)
	}
	if record == nil || record.Pending == nil {
		observed["classification"] = "foreign-unified-or-unsupported"
		return finish(false, nil)
	}
	receipt, err := frrMigrationPendingReceipt(m, owner, mode)
	if err != nil {
		return finish(false, fmt.Errorf("FRR migration preparation unavailable"))
	}
	var pendingSpec frrMigrationSpec
	if json.Unmarshal(record.Pending.Request.Spec, &pendingSpec) != nil || receipt.Digest != pendingSpec.ApprovedDigest || receipt.PreHash != record.Pending.PreHash || receipt.PostHash != record.Pending.PostHash || !reflect.DeepEqual(receipt.Before, record.Pending.Before) {
		return finish(false, fmt.Errorf("FRR migration receipt does not match journal"))
	}
	ready, err := frrMigrationActivated(ctx, db, receipt, owner)
	observed["classification"] = "migration-pending"
	return finish(ready, err)
}
