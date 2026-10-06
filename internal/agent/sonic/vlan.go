// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"sort"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

type vlanCommand struct{ *redis.Cmd }

// A replay after a lost apply reply could return a validation conflict and hide
// the first attempt's applied-but-unsaved changes. Let the caller reconcile.
func (*vlanCommand) NoRetry() bool { return true }

// GetVLAN reads a consistent CONFIG_DB snapshot without saving or changing it.
// Absence is NOT_FOUND; malformed or unreadable configuration is not absence.
func (m *SonicAgent) GetVLAN(ctx context.Context, id uint32) (*agent.VLAN, *agent.Status) {
	return m.vlan(ctx, &agent.VLAN{ID: id}, false)
}

// EnsureVLAN only creates VLANs and adds members. Save errors never trigger a
// rollback: D-Bus may have saved successfully before its reply was lost.
//
// There is no durable private dirty marker in SONiC's configuration schema.
// Every successful Ensure, even a no-op or the first call after an agent restart,
// therefore saves the whole configuration. configDirty also alerts the existing
// interface setters to uncertain persistence. It is not a durable journal;
// agent/Redis/host crashes still require reconciliation of the desired state.
func (m *SonicAgent) EnsureVLAN(ctx context.Context, desired *agent.VLAN) (*agent.VLAN, *agent.Status) {
	return m.vlan(ctx, desired, true)
}

func (m *SonicAgent) vlan(ctx context.Context, desired *agent.VLAN, ensure bool) (*agent.VLAN, *agent.Status) {
	if desired == nil || desired.ID < 1 || desired.ID > 4094 {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "VLAN ID must be between 1 and 4094")
	}
	args := []any{fmt.Sprint(desired.ID), "0"}
	if ensure {
		args[1] = "1"
		seen := make(map[string]bool, len(desired.Members))
		for _, member := range desired.Members {
			if !vlanMemberNameValid(member.InterfaceName) {
				return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "VLAN members must use canonical Ethernet or PortChannel names")
			}
			if member.TaggingMode != "tagged" && member.TaggingMode != "untagged" {
				return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "VLAN tagging mode must be tagged or untagged")
			}
			if seen[member.InterfaceName] {
				return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "duplicate desired VLAN member: "+member.InterfaceName)
			}
			seen[member.InterfaceName] = true
			args = append(args, member.InterfaceName, member.TaggingMode)
		}
		unlock, status := m.lockOrdinaryConfig(ctx, desired.ID)
		if status != nil {
			return nil, status
		}
		defer unlock()
	}
	if err := ctx.Err(); err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	rdb, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, fmt.Sprintf("connect to CONFIG_DB: %v", err))
	}
	// EVAL is intentionally self-contained: validation, broad key discovery and
	// additions run without interleaving even with writers that do not cooperate
	// with this agent. WATCH on discovered keys alone cannot catch phantom keys.
	command := &vlanCommand{redis.NewCmd(ctx, append([]any{"eval", vlanScript, 1, fmt.Sprintf("VLAN|Vlan%d", desired.ID)}, args...)...)}
	err = rdb.Process(ctx, command)
	var values []any
	if err == nil {
		values, err = command.Slice()
	}
	if err != nil {
		if ensure {
			m.configDirty = true
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, fmt.Sprintf("VLAN apply/persistence outcome uncertain; configuration is dirty, retry EnsureVLAN: %v", err))
		}
		return nil, agenterrors.NewErrorStatus(agenterrors.REDIS_HGET_FAIL, fmt.Sprintf("read VLAN: %v", err))
	}
	// The script's response is {status code, message, flattened member pairs}.
	if len(values) != 3 {
		if ensure {
			m.configDirty = true
		}
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "invalid Redis VLAN response; apply/persistence outcome uncertain")
	}
	code, codeOK := values[0].(int64)
	message, messageOK := values[1].(string)
	pairs, pairsOK := values[2].([]any)
	if !codeOK || !messageOK || !pairsOK || len(pairs)%2 != 0 {
		if ensure {
			m.configDirty = true
		}
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "invalid Redis VLAN response; apply/persistence outcome uncertain")
	}
	if code != 0 {
		return nil, agenterrors.NewErrorStatus(uint32(code), message)
	}
	result := &agent.VLAN{ID: desired.ID, Members: make([]agent.VLANMember, 0, len(pairs)/2)}
	for i := 0; i < len(pairs); i += 2 {
		name, nameOK := pairs[i].(string)
		mode, modeOK := pairs[i+1].(string)
		if !nameOK || !modeOK {
			if ensure {
				m.configDirty = true
			}
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "invalid Redis VLAN members; apply/persistence outcome uncertain")
		}
		result.Members = append(result.Members, agent.VLANMember{InterfaceName: name, TaggingMode: mode})
	}
	sort.Slice(result.Members, func(i, j int) bool { return result.Members[i].InterfaceName < result.Members[j].InterfaceName })
	if ensure {
		m.configDirty = true
		if status := m.saveConfigLocked(ctx); status != nil && status.Code != 0 {
			return nil, agenterrors.NewErrorStatus(status.Code, "VLAN configuration applied; persistence uncertain, configuration is dirty; retry EnsureVLAN: "+status.Message)
		}
		m.configDirty = false
	}
	return result, nil
}
