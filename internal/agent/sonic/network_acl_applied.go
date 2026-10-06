// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"strconv"
	"strings"
)

// sonic-sairedis 202511 lib/VirtualObjectIdManager.cpp encodes base object
// types in bits 55..48, with the extension flag in bit 39. RIDs are SDK opaque:
// only VIDs may be decoded this way. ASIC_STATE alone is requested state;
// syncd installs VIDTORID when an object has a real SAI identity.
var aclObjectTypes = map[string]uint64{
	"PORT": 1, "LAG": 2, "ACL_TABLE": 7, "ACL_ENTRY": 8,
	"ACL_COUNTER": 9, "ACL_TABLE_GROUP": 11, "ACL_TABLE_GROUP_MEMBER": 12,
}

func aclParseOID(oid string) (uint64, bool) {
	if !strings.HasPrefix(oid, "oid:0x") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(oid, "oid:0x"), 16, 64)
	return n, err == nil && n != 0 && oid == "oid:0x"+strconv.FormatUint(n, 16)
}

type aclApplied struct {
	ids       map[string]string
	aliases   map[string]int
	used      map[string]string
	domain    uint64
	hasDomain bool
}

func aclReadApplied(ctx context.Context, read aclReader) (*aclApplied, error) {
	ids, err := read(ctx, "ASIC_DB", "VIDTORID")
	if err != nil {
		return nil, err
	}
	a := &aclApplied{ids: ids, aliases: map[string]int{}, used: map[string]string{}}
	for _, rid := range ids {
		a.aliases[rid]++
	}
	return a, nil
}

func (a *aclApplied) object(vid, typ string) bool {
	n, ok := aclParseOID(vid)
	want, known := aclObjectTypes[typ]
	if !ok || !known || n>>48&0xff != want || n&(1<<39) != 0 {
		return false
	}
	// Every object in this chain must belong to the same switch/context.
	domain := n & 0xff00ff0000000000
	if a.hasDomain && a.domain != domain {
		return false
	}
	rid := a.ids[vid]
	if _, ok := aclParseOID(rid); !ok || a.aliases[rid] != 1 {
		return false
	}
	a.domain, a.hasDomain = domain, true
	a.used[vid] = rid
	return true
}

// Do not combine translations from before and after a syncd delete/recreate.
// Unrelated objects may converge concurrently without invalidating this target.
func (a *aclApplied) stable(ctx context.Context, read aclReader) (bool, error) {
	latest, err := aclReadApplied(ctx, read)
	if err != nil {
		return false, err
	}
	for vid, rid := range a.used {
		if latest.ids[vid] != rid || latest.aliases[rid] != 1 {
			return false, nil
		}
	}
	return true, ctx.Err()
}
