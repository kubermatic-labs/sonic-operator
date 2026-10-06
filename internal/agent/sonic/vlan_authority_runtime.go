// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const vlanAuthorityRuntimeTimeout = 10 * time.Second

// Read only the target VLAN in one Redis observation. APPL_DB contains extra
// operational fields; compare existence, complete membership and tagging modes,
// not CONFIG_DB's exact hash shape. This is not ASIC/forwarding verification.
const vlanAuthorityRuntimeScript = `
local target = cjson.decode(ARGV[2])
local parent = 'VLAN_TABLE:Vlan' .. ARGV[1]
local prefix = 'VLAN_MEMBER_TABLE:Vlan' .. ARGV[1] .. ':'
local configParent = 'VLAN|Vlan' .. ARGV[1]
local configPrefix = 'VLAN_MEMBER|Vlan' .. ARGV[1] .. '|'
if (redis.call('EXISTS', parent) == 1) ~= (target[configParent] ~= nil) then return 0 end
if target[configParent] and redis.call('TYPE', parent).ok ~= 'hash' then return 0 end
local seen = {}
for _, key in ipairs(redis.call('KEYS', prefix .. '*')) do
    local configKey = configPrefix .. string.sub(key, string.len(prefix) + 1)
    if not target[configKey] or redis.call('HGET', key, 'tagging_mode') ~= target[configKey]['tagging_mode'] then return 0 end
    seen[configKey] = true
end
for key, _ in pairs(target) do
    if key ~= configParent and not seen[key] then return 0 end
end
return 1
`

func (m *SonicAgent) checkVLANAuthorityRuntime(ctx context.Context, id uint32, target vlanChangeDB) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.verifyVLANRuntime != nil {
		return m.verifyVLANRuntime(ctx, id, target)
	}
	// Do not use Connect's background-context health probes in a bounded wait.
	// go-redis connects lazily and this observation carries the deadline through
	// dialing and I/O. The same pool remains available to ordinary agent methods.
	m.poolMutex.Lock()
	if m.clientPool == nil {
		m.clientPool = map[string]*redis.Client{}
	}
	rdb := m.clientPool["APPL_DB"]
	if rdb == nil {
		rdb = redis.NewClient(&redis.Options{Addr: m.redisAddr, DB: getRedisDBIDByName("APPL_DB"),
			DialTimeout: RedisDefaultTimeout, ReadTimeout: RedisReadTimeout, WriteTimeout: RedisWriteTimeout,
			PoolTimeout: RedisDefaultTimeout, MaxRetries: -1, ContextTimeoutEnabled: true, DisableIndentity: true})
		m.clientPool["APPL_DB"] = rdb
	}
	m.poolMutex.Unlock()
	payload, err := json.Marshal(target)
	if err != nil {
		return err
	}
	value, err := rdb.Eval(ctx, vlanAuthorityRuntimeScript, nil, id, string(payload)).Int64()
	if err != nil {
		return fmt.Errorf("APPL_DB observation failed: %w", err)
	}
	if value != 1 {
		return fmt.Errorf("APPL_DB VLAN membership has not converged")
	}
	return nil
}

func (m *SonicAgent) waitVLANAuthorityRuntime(ctx context.Context, id uint32, target vlanChangeDB) error {
	ctx, cancel := context.WithTimeout(ctx, vlanAuthorityRuntimeTimeout)
	defer cancel()
	for {
		err := m.checkVLANAuthorityRuntime(ctx, id, target)
		if err == nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ctx.Err(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
