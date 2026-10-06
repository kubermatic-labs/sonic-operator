// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

// CONFIG_DB is small, standalone Redis. Discover ALL keys inside EVAL, including
// phantoms. Reject expiring keys and non-hashes except SONiC's exact initialization
// marker. Its reserved row keeps presence in CAS and cannot collide with a hash:
// that key must be a persistent string "1" on every read and CAS.
// Canonical JSON sorts both keys and fields;
// the exact bytes are compared server-side, never a collision-prone Lua hash.
// Only the SHA-256 fingerprint and understood target hashes enter the journal.
const vlanChangeSnapshotScript = `
local keys = redis.call('KEYS', '*')
table.sort(keys)
local rows = {}
for _, key in ipairs(keys) do
    local kind = redis.call('TYPE', key).ok
    if redis.call('PTTL', key) ~= -1 then
        return redis.error_reply('unsupported CONFIG_DB type or expiration')
    end
    local values = {}
    if key == 'CONFIG_DB_INITIALIZED' then
        if kind ~= 'string' or redis.call('GET', key) ~= '1' then
            return redis.error_reply('unsupported CONFIG_DB initialization marker')
        end
        table.insert(values, '"__sonic_string__":"1"')
    else
        if kind ~= 'hash' then
            return redis.error_reply('unsupported CONFIG_DB type or expiration')
        end
        local fields = redis.call('HKEYS', key)
        table.sort(fields)
        for _, field in ipairs(fields) do
            table.insert(values, cjson.encode(field) .. ':' .. cjson.encode(redis.call('HGET', key, field)))
        end
    end
    table.insert(rows, '{"key":' .. cjson.encode(key) .. ',"fields":{' .. table.concat(values, ',') .. '}}')
end
local snapshot = '[' .. table.concat(rows, ',') .. ']'
`

const vlanChangeReadScript = vlanChangeSnapshotScript + `return snapshot`

// Validate the complete payload before writes (Lua errors do not undo writes).
// Applying a field delta rather than replacing hashes preserves unrelated fields.
const vlanChangeCASScript = vlanChangeSnapshotScript + `
if snapshot ~= ARGV[1] then return 0 end
local changes = cjson.decode(ARGV[2])
for _, change in ipairs(changes) do
    if type(change.key) ~= 'string' or type(change.remove) ~= 'table' or type(change.set) ~= 'table' then
        return redis.error_reply('invalid target delta')
    end
    for _, field in ipairs(change.remove) do
        if type(field) ~= 'string' then return redis.error_reply('invalid removed field') end
    end
    for field, value in pairs(change.set) do
        if type(field) ~= 'string' or type(value) ~= 'string' then return redis.error_reply('invalid set field') end
    end
end
for _, change in ipairs(changes) do
    for _, field in ipairs(change.remove) do redis.call('HDEL', change.key, field) end
    for field, value in pairs(change.set) do redis.call('HSET', change.key, field, value) end
end
return 1
`
