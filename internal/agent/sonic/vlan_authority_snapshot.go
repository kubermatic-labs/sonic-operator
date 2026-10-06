// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"sort"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

// The full CONFIG_DB stays in memory only. Durable/RPC data contains target
// membership and SHA-256 fingerprints, never unrelated fields or credentials.
type vlanChangeDB map[string]map[string]string

func vlanChangeHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func vlanAuthorityHash(db vlanChangeDB) string {
	data, _ := json.Marshal(db)
	return vlanChangeHash(data)
}
func vlanAuthorityDigest(db vlanChangeDB, id uint32) string {
	return vlanChangeHash([]byte(fmt.Sprintf("vlan-authority-v1:%d:%s", id, vlanAuthorityHash(db))))
}
func vlanAuthorityDigestValid(d string) bool {
	decoded, err := hex.DecodeString(d)
	return err == nil && len(decoded) == sha256.Size && d == strings.ToLower(d)
}

func validateVLANAuthority(r *agent.VLANAuthorityRequest) error {
	if r == nil || r.OwnerID == "" || len(r.OwnerID) > 256 {
		return fmt.Errorf("owner UID required (maximum 256 bytes)")
	}
	if r.VLAN == nil || r.VLAN.ID < 1 || r.VLAN.ID > 4094 {
		return fmt.Errorf("VLAN ID must be between 1 and 4094")
	}
	if r.AdoptionDigest != "" && !vlanAuthorityDigestValid(r.AdoptionDigest) {
		return fmt.Errorf("adoption digest must be lowercase SHA256")
	}
	seen := map[string]bool{}
	for _, member := range r.VLAN.Members {
		if _, valid := ethernetNumber(member.InterfaceName); !valid {
			return fmt.Errorf("member must use a canonical Ethernet name")
		}
		if member.TaggingMode != "tagged" && member.TaggingMode != "untagged" {
			return fmt.Errorf("tagging mode must be tagged or untagged")
		}
		if seen[member.InterfaceName] {
			return fmt.Errorf("duplicate desired member")
		}
		seen[member.InterfaceName] = true
	}
	return nil
}

func (m *SonicAgent) vlanChangeSnapshot(ctx context.Context) (vlanChangeDB, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	rdb, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, "", err
	}
	cmd := &vlanCommand{redis.NewCmd(ctx, "eval", vlanChangeReadScript, 0)}
	if err := rdb.Process(ctx, cmd); err != nil {
		return nil, "", fmt.Errorf("CONFIG_DB snapshot failed: %w", err)
	}
	raw, err := cmd.Text()
	if err != nil {
		return nil, "", err
	}
	var rows []struct {
		Key    string            `json:"key"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, "", fmt.Errorf("invalid CONFIG_DB snapshot")
	}
	db := make(vlanChangeDB, len(rows))
	for _, row := range rows {
		db[row.Key] = row.Fields
	}
	return db, raw, nil
}

func vlanChangeTarget(db vlanChangeDB, id uint32) vlanChangeDB {
	key := fmt.Sprintf("VLAN|Vlan%d", id)
	prefix := fmt.Sprintf("VLAN_MEMBER|Vlan%d|", id)
	out := vlanChangeDB{}
	for k, fields := range db {
		if k == key || strings.HasPrefix(k, prefix) {
			out[k] = maps.Clone(fields)
		}
	}
	return out
}

func vlanChangeView(db vlanChangeDB, id uint32) *agent.VLAN {
	if db[fmt.Sprintf("VLAN|Vlan%d", id)] == nil {
		return nil
	}
	v := &agent.VLAN{ID: id, Members: []agent.VLANMember{}}
	prefix := fmt.Sprintf("VLAN_MEMBER|Vlan%d|", id)
	for key, fields := range db {
		if strings.HasPrefix(key, prefix) {
			v.Members = append(v.Members, agent.VLANMember{InterfaceName: strings.TrimPrefix(key, prefix), TaggingMode: fields["tagging_mode"]})
		}
	}
	sort.Slice(v.Members, func(i, j int) bool { return v.Members[i].InterfaceName < v.Members[j].InterfaceName })
	return v
}

func vlanAuthorityDesired(r *agent.VLANAuthorityRequest) vlanChangeDB {
	target := vlanChangeDB{}
	if r.Delete {
		return target
	}
	target[fmt.Sprintf("VLAN|Vlan%d", r.VLAN.ID)] = map[string]string{"vlanid": fmt.Sprint(r.VLAN.ID)}
	for _, member := range r.VLAN.Members {
		target[fmt.Sprintf("VLAN_MEMBER|Vlan%d|%s", r.VLAN.ID, member.InterfaceName)] = map[string]string{"tagging_mode": member.TaggingMode}
	}
	return target
}

// vlanmgr does not update an existing member's mode. Remove changed/pruned
// members first, keeping the parent and unchanged members until APPL_DB catches
// up. In particular, remove an old untagged port before adding its replacement.
func vlanAuthorityIntermediate(before, after vlanChangeDB) vlanChangeDB {
	modeChange := false
	intermediate := maps.Clone(before)
	for key, fields := range before {
		if !strings.HasPrefix(key, "VLAN_MEMBER|") {
			continue
		}
		if next, ok := after[key]; ok && fields["tagging_mode"] != next["tagging_mode"] {
			modeChange = true
			delete(intermediate, key)
		} else if !ok {
			delete(intermediate, key)
		}
	}
	if !modeChange {
		return nil
	}
	return intermediate
}

func vlanAuthorityReplaceTarget(db, before, after vlanChangeDB) vlanChangeDB {
	post := maps.Clone(db)
	for key := range before {
		delete(post, key)
	}
	for key, fields := range after {
		post[key] = fields
	}
	return post
}

// No legacy members@ or opaque target fields are ever pruned or journaled.
func vlanAuthorityTargetSafe(target vlanChangeDB, id uint32) error {
	key := fmt.Sprintf("VLAN|Vlan%d", id)
	if len(target) > 0 && target[key] == nil {
		return fmt.Errorf("orphaned target VLAN members")
	}
	for k, fields := range target {
		if k == key {
			if len(fields) != 1 || fields["vlanid"] != fmt.Sprint(id) {
				return fmt.Errorf("unknown target VLAN fields, legacy members@ or invalid vlanid")
			}
			continue
		}
		name := strings.TrimPrefix(k, fmt.Sprintf("VLAN_MEMBER|Vlan%d|", id))
		if _, valid := ethernetNumber(name); !valid {
			return fmt.Errorf("noncanonical or LAG VLAN member")
		}
		if len(fields) != 1 || (fields["tagging_mode"] != "tagged" && fields["tagging_mode"] != "untagged") {
			return fmt.Errorf("unknown member fields or invalid tagging mode")
		}
	}
	return nil
}

var (
	vlanAuthorityLoggerName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
	// SONiC 202511 portconfig.py BRKOUT_PATTERN, fully anchored and requiring
	// positive counts/speeds and nonempty lists. Platform capability is not inferred.
	vlanAuthorityBreakoutMode = regexp.MustCompile(`^[1-9][0-9]{0,5}x[1-9][0-9]{0,5}G?(\[[1-9][0-9]{0,5}G?(,[1-9][0-9]{0,5}G?)*\])?(\([1-9][0-9]{0,5}\))?(\+[1-9][0-9]{0,5}x[1-9][0-9]{0,5}G?(\[[1-9][0-9]{0,5}G?(,[1-9][0-9]{0,5}G?)*\])?(\([1-9][0-9]{0,5}\))?)*$`)
)

func vlanAuthoritySafe(db vlanChangeDB, id uint32, target vlanChangeDB) error {
	if err := vlanAuthorityTargetSafe(target, id); err != nil {
		return err
	}
	vlan := fmt.Sprintf("Vlan%d", id)
	key, prefix := "VLAN|"+vlan, "VLAN_MEMBER|"+vlan+"|"
	ref := regexp.MustCompile(`(?i)(^|[^a-z0-9])vlan` + fmt.Sprint(id) + `([^0-9]|$)`)
	ports := map[string]string{}
	for k, fields := range target {
		if strings.HasPrefix(k, prefix) {
			ports[strings.TrimPrefix(k, prefix)] = fields["tagging_mode"]
		}
	}
	for name := range ports {
		if len(db["PORT|"+name]) == 0 {
			return fmt.Errorf("desired or removed member PORT not found")
		}
	}
	for k, fields := range db {
		if k == key || strings.HasPrefix(k, prefix) {
			continue
		}
		// These exact operational grammars contain no VLAN/port references.
		// Validate before skipping heuristics; retain every row in snapshots/CAS.
		table, identity, _ := strings.Cut(k, "|")
		switch table {
		case "LOGGER":
			if !vlanAuthorityLoggerName.MatchString(identity) {
				return fmt.Errorf("malformed LOGGER identity")
			}
			// sonic-logger.yang: LOGLEVEL is mandatory; LOGOUTPUT defaults to SYSLOG.
			switch fields["LOGLEVEL"] {
			case "EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG",
				"SAI_LOG_LEVEL_CRITICAL", "SAI_LOG_LEVEL_ERROR", "SAI_LOG_LEVEL_WARN",
				"SAI_LOG_LEVEL_NOTICE", "SAI_LOG_LEVEL_INFO", "SAI_LOG_LEVEL_DEBUG":
			default:
				return fmt.Errorf("invalid LOGGER LOGLEVEL")
			}
			for field, value := range fields {
				switch field {
				case "LOGLEVEL":
				case "LOGOUTPUT":
					if value != "SYSLOG" && value != "STDOUT" && value != "STDERR" {
						return fmt.Errorf("invalid LOGGER LOGOUTPUT")
					}
				case "require_manual_refresh":
					if value != "true" && value != "false" {
						return fmt.Errorf("invalid LOGGER require_manual_refresh")
					}
				default:
					return fmt.Errorf("unknown LOGGER field")
				}
			}
			continue
		case "BREAKOUT_CFG":
			if _, valid := ethernetNumber(identity); !valid {
				return fmt.Errorf("malformed BREAKOUT_CFG port")
			}
			if len(fields) != 1 || len(fields["brkout_mode"]) > 64 || !vlanAuthorityBreakoutMode.MatchString(fields["brkout_mode"]) {
				return fmt.Errorf("unknown BREAKOUT_CFG fields or invalid brkout_mode")
			}
			continue
		}
		if ref.MatchString(k) {
			return fmt.Errorf("VLAN dependency in CONFIG_DB key")
		}
		// Unknown VLAN grammars may encode ranges, aliases or selectors such as
		// "all". Searching only for the decimal ID would silently miss them.
		knownVLAN := strings.HasPrefix(k, "VLAN|")
		knownMember := strings.HasPrefix(k, "VLAN_MEMBER|")
		if strings.Contains(strings.ToLower(k), "vlan") && !knownVLAN && !knownMember {
			return fmt.Errorf("unknown VLAN dependency table or key")
		}
		if knownVLAN || knownMember {
			parts := strings.Split(k, "|")
			otherID, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "Vlan"), 10, 32)
			if err != nil || otherID < 1 || otherID > 4094 || parts[1] != fmt.Sprintf("Vlan%d", otherID) {
				return fmt.Errorf("malformed VLAN dependency identity")
			}
			if knownVLAN && (len(parts) != 2 || fields["vlanid"] != fmt.Sprint(otherID)) {
				return fmt.Errorf("malformed VLAN dependency")
			}
			if knownMember && (len(parts) != 3 || len(fields) != 1 || (fields["tagging_mode"] != "tagged" && fields["tagging_mode"] != "untagged")) {
				return fmt.Errorf("malformed VLAN member dependency")
			}
		}
		for field, value := range fields {
			if ref.MatchString(field) || ref.MatchString(value) {
				return fmt.Errorf("VLAN dependency in CONFIG_DB field")
			}
			if strings.Contains(strings.ToLower(field), "vlan") {
				if knownVLAN && field == "vlanid" {
					continue
				}
				return fmt.Errorf("unknown VLAN reference field")
			}
		}
		for name, mode := range ports {
			if k == "PORT|"+name {
				continue
			}
			if strings.HasPrefix(k, "VLAN_MEMBER|") && strings.HasSuffix(k, "|"+name) {
				parts := strings.Split(k, "|")
				otherID, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "Vlan"), 10, 32)
				if len(parts) != 3 || err != nil || otherID < 1 || otherID > 4094 || parts[1] != fmt.Sprintf("Vlan%d", otherID) || len(fields) != 1 || (fields["tagging_mode"] != "tagged" && fields["tagging_mode"] != "untagged") {
					return fmt.Errorf("malformed competing VLAN membership")
				}
				if mode == "untagged" && fields["tagging_mode"] == "untagged" {
					return fmt.Errorf("competing untagged VLAN membership")
				}
				continue
			}
			portRef := regexp.MustCompile(`(^|[^a-zA-Z0-9])` + name + `([^0-9]|$)`)
			if portRef.MatchString(k) {
				return fmt.Errorf("LAG, routed or unknown port dependency")
			}
			for field, value := range fields {
				if portRef.MatchString(field) || portRef.MatchString(value) {
					return fmt.Errorf("unknown port reference")
				}
			}
		}
	}
	return nil
}

func (m *SonicAgent) casVLANChange(ctx context.Context, raw string, from, to vlanChangeDB) (bool, error) {
	type delta struct {
		Key    string            `json:"key"`
		Remove []string          `json:"remove"`
		Set    map[string]string `json:"set"`
	}
	keys := map[string]bool{}
	for k := range from {
		keys[k] = true
	}
	for k := range to {
		keys[k] = true
	}
	changes := []delta{}
	for k := range keys {
		d := delta{Key: k, Remove: []string{}, Set: map[string]string{}}
		for field := range from[k] {
			if _, ok := to[k][field]; !ok {
				d.Remove = append(d.Remove, field)
			}
		}
		for field, value := range to[k] {
			if old, ok := from[k][field]; !ok || old != value {
				d.Set[field] = value
			}
		}
		sort.Strings(d.Remove)
		if len(d.Remove) > 0 || len(d.Set) > 0 {
			changes = append(changes, d)
		}
	}
	// Remove members before deleting their parent; create the parent first for adds.
	sort.Slice(changes, func(i, j int) bool {
		iParent := strings.HasPrefix(changes[i].Key, "VLAN|")
		jParent := strings.HasPrefix(changes[j].Key, "VLAN|")
		if iParent != jParent {
			if len(to) == 0 {
				return !iParent
			}
			return iParent
		}
		return changes[i].Key < changes[j].Key
	})
	payload, err := json.Marshal(changes)
	if err != nil {
		return false, err
	}
	rdb, err := m.Connect("CONFIG_DB")
	if err != nil {
		return false, err
	}
	cmd := &vlanCommand{redis.NewCmd(ctx, "eval", vlanChangeCASScript, 0, raw, string(payload))}
	if err := rdb.Process(ctx, cmd); err != nil {
		return false, err
	}
	value, err := cmd.Int64()
	if err != nil {
		return false, err
	}
	if value != 0 && value != 1 {
		return false, fmt.Errorf("invalid CAS response")
	}
	return value == 1, nil
}
