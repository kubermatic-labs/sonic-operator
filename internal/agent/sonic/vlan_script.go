// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

// SONiC CONFIG_DB is a standalone Redis DB, not Redis Cluster. KEYS inside this
// bounded configuration operation intentionally covers new keys as well as old
// ones atomically. SCAN/WATCH outside the script would miss concurrent LAG,
// routed-interface and cross-VLAN untagged additions. All reads and validation
// precede every write: Redis Lua runtime errors do not roll back earlier writes.
// Status codes below are internal/agent/errors BAD_REQUEST/NOT_FOUND/ALREADY_EXISTS.
const vlanScript = `
local key = KEYS[1]
local id = ARGV[1]
local ensure = ARGV[2] == '1'
local prefix = 'VLAN_MEMBER|Vlan' .. id .. '|'
local exists = redis.call('EXISTS', key) == 1
local function reject(code, message)
    return {code, message, {}}
end

if exists then
    if redis.call('HGET', key, 'vlanid') ~= id then
        return reject(101, 'existing VLAN has missing or conflicting vlanid')
    end
elseif not ensure then
    return reject(201, 'VLAN not found')
end

local members = {}
for _, memberKey in ipairs(redis.call('KEYS', prefix .. '*')) do
    local name = string.sub(memberKey, #prefix + 1)
    local mode = redis.call('HGET', memberKey, 'tagging_mode')
    if name == '' or string.find(name, '|', 1, true) or (mode ~= 'tagged' and mode ~= 'untagged') then
        return reject(101, 'malformed existing VLAN member: ' .. memberKey)
    end
    members[name] = mode
end

local additions = {}
if ensure then
    for i = 3, #ARGV, 2 do
        local name = ARGV[i]
        local mode = ARGV[i + 1]
        if #redis.call('HGETALL', 'PORT|' .. name) == 0 then
            return reject(201, 'PORT not found: ' .. name)
        end
        if #redis.call('KEYS', 'PORTCHANNEL_MEMBER|*|' .. name) > 0 then
            return reject(101, 'VLAN member belongs to a LAG: ' .. name)
        end
        if redis.call('EXISTS', 'INTERFACE|' .. name) == 1 or #redis.call('KEYS', 'INTERFACE|' .. name .. '|*') > 0 then
            return reject(101, 'VLAN member is a routed interface: ' .. name)
        end
        if members[name] and members[name] ~= mode then
            return reject(202, 'existing VLAN member has conflicting tagging mode: ' .. name)
        end
        if mode == 'untagged' then
            for _, otherKey in ipairs(redis.call('KEYS', 'VLAN_MEMBER|*|' .. name)) do
                if otherKey ~= prefix .. name and redis.call('HGET', otherKey, 'tagging_mode') == 'untagged' then
                    return reject(202, 'PORT already belongs to another untagged VLAN: ' .. name)
                end
            end
        end
        if not members[name] then
            table.insert(additions, {name, mode})
        end
    end
end

-- Build the response before applying anything, leaving only HSET operations
-- after validation. Existing hashes/fields (including legacy members@) are kept.
for _, addition in ipairs(additions) do
    members[addition[1]] = addition[2]
end
local result = {}
for name, mode in pairs(members) do
    table.insert(result, name)
    table.insert(result, mode)
end

if ensure then
    if not exists then
        redis.call('HSET', key, 'vlanid', id)
    end
    for _, addition in ipairs(additions) do
        redis.call('HSET', prefix .. addition[1], 'tagging_mode', addition[2])
    end
end
return {0, '', result}
`
