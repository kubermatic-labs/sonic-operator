// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

var _ agent.VLANAuthorityAgent = (*SonicAgent)(nil)

func vlanAuthorityResult(db vlanChangeDB, id uint32, r *vlanAuthorityRecord) *agent.VLANAuthorityResult {
	result := &agent.VLANAuthorityResult{VLAN: vlanChangeView(db, id), Digest: vlanAuthorityDigest(db, id), OwnershipKnown: true}
	if r == nil {
		return result
	}
	result.OwnerID = r.OwnerID
	expected := r.Confirmed
	if r.Pending != nil {
		expected = r.Pending.After
	}
	result.RuntimeVerified = db != nil && expected != nil && reflect.DeepEqual(vlanChangeTarget(db, id), expected) && vlanAuthoritySafe(db, id, expected) == nil
	result.PersistenceVerified = result.RuntimeVerified && r.Pending == nil && vlanAuthorityHash(db) == r.Fingerprint
	return result
}

// A CONFIG_DB match alone is not proof that vlanmgr consumed the operation.
// Reads and known no-ops observe once; mutating recovery uses the bounded wait.
func (m *SonicAgent) observedVLANAuthorityResult(ctx context.Context, db vlanChangeDB, id uint32, r *vlanAuthorityRecord) *agent.VLANAuthorityResult {
	result := vlanAuthorityResult(db, id, r)
	if result.RuntimeVerified {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if m.checkVLANAuthorityRuntime(ctx, id, vlanChangeTarget(db, id)) != nil {
			result.RuntimeVerified, result.PersistenceVerified = false, false
		}
	}
	return result
}

func (m *SonicAgent) GetVLANAuthority(ctx context.Context, id uint32) (*agent.VLANAuthorityResult, *agent.Status) {
	if id < 1 || id > 4094 {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "VLAN ID must be between 1 and 4094")
	}
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	var r *vlanAuthorityRecord
	if m.journalDir != "" {
		j, err := m.lockVLANAuthorityJournal(ctx)
		if err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
		defer j.close()
		r, err = j.load(id)
		if err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
	}
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	result := m.observedVLANAuthorityResult(ctx, db, id, r)
	result.OwnershipKnown = m.journalDir != ""
	return result, nil
}

func (m *SonicAgent) ReconcileVLANAuthority(ctx context.Context, request *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, *agent.Status) {
	if err := validateVLANAuthority(request); err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	// Never retain a caller-owned slice in a durable operation.
	r := *request
	v := *r.VLAN
	v.Members = append([]agent.VLANMember(nil), v.Members...)
	r.VLAN = &v
	id := v.ID
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	j, err := m.lockVLANAuthorityJournal(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	defer j.close()
	record, err := j.load(id)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	breakoutUnlock, err := m.guardBreakoutWrites(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, err.Error())
	}
	defer breakoutUnlock()
	db, raw, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	fail := func(code uint32, message string) (*agent.VLANAuthorityResult, *agent.Status) {
		return m.observedVLANAuthorityResult(ctx, db, id, record), agenterrors.NewErrorStatus(code, message)
	}
	if record != nil && record.OwnerID != r.OwnerID {
		return fail(agenterrors.ALREADY_EXISTS, "VLAN is owned by a different CR UID; ownership cannot transfer")
	}
	if record != nil && record.Pending != nil {
		changed := !reflect.DeepEqual(vlanAuthorityDesired(&r), record.Pending.After)
		result, status := m.recoverVLANAuthority(ctx, j, record, db, raw)
		if status == nil && changed {
			return result, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "previous pending operation recovered; new desired configuration pending, retry reconcile")
		}
		return result, status
	}
	// Whole-DB persistence must not advance around another VLAN's unresolved
	// write. Otherwise our save could invalidate its pending pre/post proof.
	if err := j.checkPending(id); err != nil {
		return fail(agenterrors.ALREADY_EXISTS, err.Error())
	}
	if r.Delete && record == nil {
		return fail(agenterrors.ALREADY_EXISTS, "deletion requires existing ownership by this CR UID")
	}
	before, after := vlanChangeTarget(db, id), vlanAuthorityDesired(&r)
	if err := vlanAuthoritySafe(db, id, before); err != nil {
		return fail(agenterrors.BAD_REQUEST, err.Error())
	}
	if err := vlanAuthoritySafe(db, id, after); err != nil {
		return fail(agenterrors.BAD_REQUEST, err.Error())
	}
	if record == nil && len(before) != 0 && r.AdoptionDigest != vlanAuthorityDigest(db, id) {
		return fail(agenterrors.ALREADY_EXISTS, "existing VLAN takeover requires adoptionDigest matching the current snapshot digest")
	}
	if record != nil && reflect.DeepEqual(before, after) && reflect.DeepEqual(record.Confirmed, after) && record.Fingerprint == vlanAuthorityHash(db) {
		result := m.observedVLANAuthorityResult(ctx, db, id, record)
		if !result.RuntimeVerified {
			return result, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "CONFIG_DB unchanged but APPL_DB not verified; inspect runtime convergence")
		}
		return result, nil
	}
	if record == nil {
		record = &vlanAuthorityRecord{Version: 1, VLANID: id, OwnerID: r.OwnerID}
	}
	// Derive the post fingerprint without persisting or exposing the raw DB.
	post := vlanAuthorityReplaceTarget(db, before, after)
	record.Pending = &vlanAuthorityPending{Request: r, Before: before, After: after, PreHash: vlanAuthorityHash(db), PostHash: vlanAuthorityHash(post)}
	if intermediate := vlanAuthorityIntermediate(before, after); intermediate != nil {
		record.Pending.Intermediate = intermediate
		record.Pending.IntermediateHash = vlanAuthorityHash(vlanAuthorityReplaceTarget(db, before, intermediate))
	}
	if err := j.store(record); err != nil {
		return fail(agenterrors.SERVER_ERROR, "pending journal write failed; retry: "+err.Error())
	}
	return m.recoverVLANAuthority(ctx, j, record, db, raw)
}

// Recovery always completes the recorded request, never the new caller's target.
// An uncertain CAS reply remains pending. A definite CAS rejection is safe to
// abandon, allowing a fresh snapshot/reapproval rather than a permanent wedge.
func (m *SonicAgent) recoverVLANAuthority(ctx context.Context, j *vlanAuthorityJournal, r *vlanAuthorityRecord, db vlanChangeDB, raw string) (*agent.VLANAuthorityResult, *agent.Status) {
	p := r.Pending
	runtimeVerified := false
	fail := func(code uint32, message string) (*agent.VLANAuthorityResult, *agent.Status) {
		result := vlanAuthorityResult(db, r.VLANID, r)
		result.RuntimeVerified = result.RuntimeVerified && runtimeVerified
		result.PersistenceVerified = false
		return result, agenterrors.NewErrorStatus(code, message)
	}
	fingerprint := vlanAuthorityHash(db)
	pre := fingerprint == p.PreHash && reflect.DeepEqual(vlanChangeTarget(db, r.VLANID), p.Before)
	post := fingerprint == p.PostHash && reflect.DeepEqual(vlanChangeTarget(db, r.VLANID), p.After)
	intermediate := p.Intermediate != nil && fingerprint == p.IntermediateHash && reflect.DeepEqual(vlanChangeTarget(db, r.VLANID), p.Intermediate)
	if !pre && !post && !intermediate {
		return fail(agenterrors.ALREADY_EXISTS, "pending VLAN operation matches neither pre, intermediate nor post snapshot; deliberate recovery required")
	}
	if err := vlanAuthoritySafe(db, r.VLANID, p.After); err != nil {
		return fail(agenterrors.ALREADY_EXISTS, "pending operation unsafe: "+err.Error())
	}
	// Upgrade persisted v1 pending mode changes only from their exact pre-state.
	// An old post-state may already be broken: verify it, never blindly replay it.
	if pre && p.Intermediate == nil {
		if target := vlanAuthorityIntermediate(p.Before, p.After); target != nil {
			p.Intermediate = target
			p.IntermediateHash = vlanAuthorityHash(vlanAuthorityReplaceTarget(db, p.Before, target))
			if err := j.store(r); err != nil {
				return fail(agenterrors.SERVER_ERROR, "pending migration journal uncertain; retry")
			}
		}
	}
	if pre && !post {
		if err := vlanAuthoritySafe(db, r.VLANID, p.Before); err != nil {
			return fail(agenterrors.ALREADY_EXISTS, "pending current state unsafe: "+err.Error())
		}
		m.configDirty = true
		target := p.After
		if p.Intermediate != nil {
			target = p.Intermediate
		}
		applied, err := m.casVLANChange(ctx, raw, p.Before, target)
		if err != nil {
			return fail(agenterrors.SERVER_ERROR, "VLAN apply outcome uncertain; retry pending operation")
		}
		if !applied {
			if r.Confirmed == nil {
				err = j.remove(r.VLANID)
			} else {
				r.Pending = nil
				err = j.store(r)
			}
			if err != nil {
				r.Pending = p
				return fail(agenterrors.SERVER_ERROR, "CAS rejected; pending journal cleanup uncertain, retry")
			}
			result := vlanAuthorityResult(db, r.VLANID, r)
			if r.Confirmed == nil {
				result.OwnerID = ""
			}
			result.RuntimeVerified, result.PersistenceVerified = false, false
			return result, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, "CONFIG_DB changed before atomic apply; refresh snapshot and retry")
		}
	}
	var err error
	db, raw, err = m.vlanChangeSnapshot(ctx)
	if err != nil {
		return fail(agenterrors.SERVER_ERROR, "post-apply observation failed; persistence pending")
	}
	if p.Intermediate != nil && vlanAuthorityHash(db) == p.IntermediateHash && reflect.DeepEqual(vlanChangeTarget(db, r.VLANID), p.Intermediate) {
		if err := m.waitVLANAuthorityRuntime(ctx, r.VLANID, p.Intermediate); err != nil {
			return fail(agenterrors.SERVER_ERROR, "member removal convergence pending; retry: "+err.Error())
		}
		// Use the complete intermediate observation as CAS expectation. Never
		// refresh the expected raw snapshot around an unrelated concurrent write.
		m.configDirty = true
		applied, err := m.casVLANChange(ctx, raw, p.Intermediate, p.After)
		if err != nil {
			return fail(agenterrors.SERVER_ERROR, "VLAN add outcome uncertain; retry pending operation")
		}
		if !applied {
			// Removal already happened. Retain all proof and block other saves.
			return fail(agenterrors.ALREADY_EXISTS, "CONFIG_DB changed before staged add; pending operation requires deliberate recovery")
		}
		db, _, err = m.vlanChangeSnapshot(ctx)
		if err != nil {
			return fail(agenterrors.SERVER_ERROR, "post-add observation failed; persistence pending")
		}
	}
	if vlanAuthorityHash(db) != p.PostHash {
		return fail(agenterrors.ALREADY_EXISTS, "configuration changed after apply; pending operation requires deliberate recovery")
	}
	if err := m.waitVLANAuthorityRuntime(ctx, r.VLANID, p.After); err != nil {
		return fail(agenterrors.SERVER_ERROR, "APPL_DB convergence pending; not persisted: "+err.Error())
	}
	runtimeVerified = true
	// Runtime waits allow other CONFIG_DB writers to run. Recheck the full
	// fingerprint before saving, not only after persistence has already happened.
	db, _, err = m.vlanChangeSnapshot(ctx)
	if err != nil || vlanAuthorityHash(db) != p.PostHash {
		return fail(agenterrors.ALREADY_EXISTS, "configuration changed while waiting for APPL_DB; pending operation requires deliberate recovery")
	}
	// Even an exact recovered post-state does not prove an earlier save succeeded.
	m.configDirty = true
	if ctx.Err() != nil {
		return fail(agenterrors.SERVER_ERROR, "persistence pending; request canceled")
	}
	if s := m.saveConfigLocked(ctx); s != nil && s.Code != 0 {
		return fail(s.Code, "persistence pending; save outcome uncertain, retry")
	}
	if ctx.Err() != nil {
		return fail(agenterrors.SERVER_ERROR, "persistence pending; canceled after save")
	}
	db, _, err = m.vlanChangeSnapshot(ctx)
	if err != nil {
		return fail(agenterrors.SERVER_ERROR, "post-save observation failed; persistence pending")
	}
	if vlanAuthorityHash(db) != p.PostHash {
		return fail(agenterrors.ALREADY_EXISTS, "configuration changed during save; pending operation requires deliberate recovery")
	}
	runtimeVerified = false
	if err := m.waitVLANAuthorityRuntime(ctx, r.VLANID, p.After); err != nil {
		return fail(agenterrors.SERVER_ERROR, "post-save APPL_DB convergence pending; retry: "+err.Error())
	}
	runtimeVerified = true
	db, _, err = m.vlanChangeSnapshot(ctx)
	if err != nil || vlanAuthorityHash(db) != p.PostHash {
		return fail(agenterrors.ALREADY_EXISTS, "configuration changed before completion; pending operation requires deliberate recovery")
	}
	oldConfirmed, oldFingerprint := r.Confirmed, r.Fingerprint
	r.Confirmed, r.Fingerprint, r.Pending = p.After, p.PostHash, nil
	if err := j.store(r); err != nil {
		r.Confirmed, r.Fingerprint, r.Pending = oldConfirmed, oldFingerprint, p
		return fail(agenterrors.SERVER_ERROR, "save acknowledged but completion journal uncertain; retry")
	}
	m.configDirty = false
	return vlanAuthorityResult(db, r.VLANID, r), nil
}

// Release is an orphan operation: exact owner only, no CONFIG_DB mutation/save.
// Missing ownership is not guessed to belong to the caller.
func (m *SonicAgent) ReleaseVLANAuthority(ctx context.Context, id uint32, owner string) *agent.Status {
	if id < 1 || id > 4094 || owner == "" || len(owner) > 256 {
		return agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "valid VLAN ID and exact owner UID required")
	}
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	j, err := m.lockVLANAuthorityJournal(ctx)
	if err != nil {
		return agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	defer j.close()
	r, err := j.load(id)
	if err != nil {
		return agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	if r == nil || r.OwnerID != owner {
		return agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, "release requires exact existing owner UID")
	}
	if r.Pending != nil {
		return agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, "cannot release ownership with pending persistence; recover first")
	}
	if err := j.remove(id); err != nil {
		return agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "release journal durability uncertain; inspect ownership before retry")
	}
	return nil
}

func (j *vlanAuthorityJournal) checkPending(id uint32) error {
	d, err := j.root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	files, err := d.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") || f.Name() == vlanAuthorityFile(id) {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(f.Name(), "vlan-"), ".json"), 10, 32)
		if err != nil || vlanAuthorityFile(uint32(n)) != f.Name() {
			return fmt.Errorf("unrecognized journal record; inspect before writes")
		}
		r, err := j.load(uint32(n))
		if err != nil {
			return err
		}
		if r == nil {
			return fmt.Errorf("journal changed while locked")
		}
		if r.Pending != nil {
			return fmt.Errorf("Vlan%d has pending persistence; reconcile its owner first", n)
		}
	}
	return nil
}

// lockOrdinaryConfig checks only the filesystem journal, not full CONFIG_DB.
// Hold both locks through mutation, save and any existing setter rollback.
// VLAN ID zero is for whole-DB saves/interface setters: block all pending work
// but allow confirmed ownership on unrelated configuration.
func (m *SonicAgent) lockOrdinaryConfig(ctx context.Context, id uint32) (func(), *agent.Status) {
	m.configMutex.Lock()
	if err := ctx.Err(); err != nil {
		m.configMutex.Unlock()
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	if m.journalDir == "" {
		breakoutUnlock, err := m.guardBreakoutWrites(ctx)
		if err != nil {
			m.configMutex.Unlock()
			return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, err.Error())
		}
		return func() { breakoutUnlock(); m.configMutex.Unlock() }, nil
	}
	j, err := m.lockVLANAuthorityJournal(ctx)
	if err != nil {
		m.configMutex.Unlock()
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	unlock := func() { j.close(); m.configMutex.Unlock() }
	if err := j.checkPending(0); err != nil {
		unlock()
		return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, err.Error())
	}
	if id != 0 {
		r, err := j.load(id)
		if err != nil {
			unlock()
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
		if r != nil {
			unlock()
			return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, "VLAN has authoritative ownership; release ownership before additive reconciliation")
		}
	}
	breakoutUnlock, err := m.guardBreakoutWrites(ctx)
	if err != nil {
		unlock()
		return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, err.Error())
	}
	return func() { breakoutUnlock(); unlock() }, nil
}
