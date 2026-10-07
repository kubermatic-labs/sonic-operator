// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"reflect"
	"time"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

var _ agent.PortBreakoutAgent = (*SonicAgent)(nil)

func (m *SonicAgent) breakoutCapability(ctx context.Context, port string, db vlanChangeDB) (*breakoutPlatform, error) {
	resolve := m.resolveBreakout
	if resolve == nil {
		resolve = m.nativeBreakoutPlatform
	}
	p, err := resolve(ctx, port, db["DEVICE_METADATA|localhost"])
	if err != nil {
		return nil, err
	}
	if err := validateBreakoutPlatform(p); err != nil {
		return nil, err
	}
	if p.Port != port {
		return nil, fmt.Errorf("resolver returned a different parent")
	}
	return p, nil
}

func (m *SonicAgent) GetPortBreakout(ctx context.Context, port string) (*agent.PortBreakout, *agent.Status) {
	if _, valid := ethernetNumber(port); !valid {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, "canonical Ethernet parent required")
	}
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Same cross-process order as all writers. No file creation on observation.
	if m.journalDir != "" {
		j, err := m.lockVLANAuthorityJournal(ctx)
		if err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
		defer j.close()
	}
	var r *breakoutRecord
	if m.breakoutJournalDir != "" {
		j, err := m.lockBreakoutJournal(ctx)
		if err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
		defer j.close()
		r, err = loadBreakoutRecord(j)
		if err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
	}
	db, _, err := m.readBreakoutDB(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	p, err := m.breakoutCapability(ctx, port, db)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	out := breakoutResult(db, p, r)
	if err := breakoutConfigMatches(db, p, out.Mode); err != nil {
		out.Message = err.Error()
		return out, nil
	}
	runtimeErr := m.checkBreakoutRuntime(ctx, p, breakoutTarget(db, p))
	latest, _, err := m.readBreakoutDB(ctx)
	if err != nil || vlanAuthorityHash(latest) != vlanAuthorityHash(db) {
		out.Message = "CONFIG_DB changed during runtime observation; retry"
		return out, nil
	}
	out.ConfigurationVerified = true
	if runtimeErr != nil {
		out.Message = runtimeErr.Error()
		return out, nil
	}
	out.RuntimeVerified = true
	out.PersistenceVerified = r != nil && !r.Pending && r.Request.Port == port && reflect.DeepEqual(r.Platform, *p) && reflect.DeepEqual(r.After, breakoutTarget(db, p)) && r.UnrelatedHash == breakoutUnrelatedHash(db, p)
	if out.PersistenceVerified {
		out.PersistenceVerified = m.breakoutPersisted(p, r.After)
		latest, _, err := m.readBreakoutDB(ctx)
		if err != nil || vlanAuthorityHash(latest) != vlanAuthorityHash(db) {
			out.ConfigurationVerified, out.RuntimeVerified, out.PersistenceVerified = false, false, false
			out.Message = "CONFIG_DB changed during persistence observation; retry"
			return out, nil
		}
	}
	if out.Pending {
		out.Message = "pending breakout blocks configuration writes; reconcile the recorded request or inspect manually"
	}
	return out, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (m *SonicAgent) ReconcilePortBreakout(ctx context.Context, request *agent.PortBreakoutRequest) (*agent.PortBreakout, *agent.Status) {
	if err := validateBreakoutRequest(request); err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	r := *request
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	if m.journalDir != "" {
		j, err := m.lockVLANAuthorityJournal(ctx)
		if err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
		}
		defer j.close()
		if err := j.checkPending(0); err != nil {
			return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, err.Error())
		}
	}
	j, err := m.lockBreakoutJournal(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	defer j.close()
	record, err := loadBreakoutRecord(j)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	if record != nil && record.Pending {
		ctx = context.WithValue(ctx, artifactRecoveryKey{}, true)
	}
	networkState, networkUnlock, err := m.guardNetworkWriteState(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, err.Error())
	}
	defer networkUnlock()
	db, raw, err := m.readBreakoutDB(ctx)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	p, err := m.breakoutCapability(ctx, r.Port, db)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	fail := func(message string) (*agent.PortBreakout, *agent.Status) {
		out := breakoutResult(db, p, record)
		out.Message = message
		return out, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, message)
	}
	if record != nil && record.Pending {
		if record.Request != r || !reflect.DeepEqual(record.Platform, *p) {
			return fail("another request/platform has pending breakout; recover the exact recorded request first")
		}
		return m.finishBreakout(ctx, j, record, networkState, db, raw)
	}
	if p.Modes[r.Mode] == nil {
		return fail("requested mode is not an exact platform capability")
	}
	currentMode := db["BREAKOUT_CFG|"+p.Port]["brkout_mode"]
	if err := breakoutConfigMatches(db, p, currentMode); err != nil {
		return fail("current breakout configuration is not exact: " + err.Error())
	}
	before := breakoutTarget(db, p)
	native, after := before, before
	transition := currentMode != r.Mode
	if r.AdoptOnly && transition {
		return fail("adoption requires the existing exact requested layout; native transition forbidden")
	}
	if transition {
		if err := breakoutNetworkDependencies(p, networkState); err != nil {
			return fail(err.Error())
		}
		if err := breakoutDependencies(db, p); err != nil {
			return fail(err.Error())
		}
		native, after, err = breakoutTargets(db, p, r)
		if err != nil {
			return fail(err.Error())
		}
	}
	// Verify the old runtime before deleting anything; a known no-op is still
	// journaled and saved, but never resets admin state on existing interfaces.
	if err := m.checkBreakoutRuntime(ctx, p, before); err != nil {
		return fail("current runtime is not verified: " + err.Error())
	}
	if err := m.checkNativeBreakoutConfig(ctx); err != nil {
		return fail(err.Error())
	}
	record = &breakoutRecord{Version: 1, Request: r, Platform: *p, Before: before, Native: native, After: after, UnrelatedHash: breakoutUnrelatedHash(db, p), Pending: true, NativeSucceeded: !transition}
	if err := storeBreakoutRecord(j, record); err != nil {
		return fail("breakout intent durability uncertain; inspect/recover before retry: " + err.Error())
	}
	// Recheck the complete pre-state and platform immediately before dispatch.
	latest, _, err := m.readBreakoutDB(ctx)
	if err != nil || vlanAuthorityHash(latest) != vlanAuthorityHash(db) {
		return fail("CONFIG_DB changed before native dispatch; pending record requires manual inspection")
	}
	latestPlatform, err := m.breakoutCapability(ctx, r.Port, latest)
	if err != nil || !reflect.DeepEqual(latestPlatform, p) {
		return fail("platform changed before native dispatch; pending record requires manual inspection")
	}
	if transition {
		m.configDirty = true
		if err := m.nativeBreakout(ctx, r.Port, r.Mode); err != nil {
			return fail("native breakout outcome unknown; never automatically repeated; inspect runtime and journal: " + err.Error())
		}
		// A durable successful return permits only attribute restoration, not a
		// second native invocation. A lost return can recover only exact After.
		record.NativeSucceeded = true
		if err := storeBreakoutRecord(j, record); err != nil {
			return fail("native completion durability uncertain; recovery requires exact desired runtime")
		}
	}
	db, raw, err = m.readBreakoutDB(ctx)
	if err != nil {
		return fail("post-command observation failed; breakout pending")
	}
	return m.finishBreakout(ctx, j, record, networkState, db, raw)
}

// Every caller retains the validated network state under its existing flock.
// Recovery must apply typed ownership checks even after native CLI completion.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (m *SonicAgent) finishBreakout(ctx context.Context, j *vlanAuthorityJournal, r *breakoutRecord, networkState *networkJournalState, db vlanChangeDB, raw string) (*agent.PortBreakout, *agent.Status) {
	p := &r.Platform
	runtimeVerified := false
	configurationVerified := false
	fail := func(message string) (*agent.PortBreakout, *agent.Status) {
		out := breakoutResult(db, p, r)
		out.RuntimeVerified = runtimeVerified
		out.ConfigurationVerified = configurationVerified
		out.Message = message
		return out, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, message)
	}
	if breakoutUnrelatedHash(db, p) != r.UnrelatedHash {
		return fail("unrelated configuration changed during pending breakout; manual inspection required")
	}
	// Only an exactly recorded no-op can coexist with populated dependencies.
	// A transition remains subject to dependency checks even after its CLI ran.
	if !reflect.DeepEqual(r.Before, r.After) || !reflect.DeepEqual(r.Native, r.After) {
		if err := breakoutNetworkDependencies(p, networkState); err != nil {
			return fail("pending breakout unsafe: " + err.Error())
		}
		if err := breakoutDependencies(db, p); err != nil {
			return fail("pending breakout unsafe: " + err.Error())
		}
	}
	target := breakoutTarget(db, p)
	if !reflect.DeepEqual(target, r.After) {
		if !r.NativeSucceeded || !reflect.DeepEqual(target, r.Native) {
			return fail("pending breakout is before, partial or foreign state; native command will not be repeated; manual inspection required")
		}
		if err := breakoutConfigMatches(db, p, r.Request.Mode); err != nil {
			return fail(err.Error())
		}
		m.configDirty = true
		applied, err := m.restoreBreakoutAttributes(ctx, raw, target, r.After)
		if err != nil || !applied {
			return fail("attribute restoration outcome uncertain or CONFIG_DB changed; breakout remains pending")
		}
	}
	// Prove the final exact target in two full snapshots before runtime waiting.
	// Runtime failure must not erase independently established config evidence.
	first, _, err := m.readBreakoutDB(ctx)
	if err != nil || breakoutConfigMatches(first, p, r.Request.Mode) != nil || breakoutUnrelatedHash(first, p) != r.UnrelatedHash || !reflect.DeepEqual(breakoutTarget(first, p), r.After) {
		return fail("configuration not exact after native command/attribute restoration")
	}
	second, _, err := m.readBreakoutDB(ctx)
	if err != nil || vlanAuthorityHash(first) != vlanAuthorityHash(second) {
		return fail("configuration unstable after native command/attribute restoration")
	}
	db = second
	configurationVerified = true
	// One shared convergence budget covers pre-save and post-save verification.
	convergenceCtx, cancel := context.WithTimeout(ctx, breakoutConvergenceTimeout)
	defer cancel()
	if err := m.waitBreakoutRuntime(convergenceCtx, p, r.After, r.UnrelatedHash); err != nil {
		latest, _, readErr := m.readBreakoutDB(ctx)
		configurationVerified = readErr == nil && vlanAuthorityHash(latest) == vlanAuthorityHash(db)
		return fail(err.Error())
	}
	runtimeVerified = true
	db, _, err = m.readBreakoutDB(ctx)
	if err != nil || breakoutUnrelatedHash(db, p) != r.UnrelatedHash || !reflect.DeepEqual(breakoutTarget(db, p), r.After) {
		runtimeVerified = false
		configurationVerified = false
		return fail("CONFIG_DB changed before save; breakout remains pending")
	}
	m.configDirty = true
	if status := m.saveConfigLocked(ctx); status != nil && status.Code != 0 {
		latest, _, readErr := m.readBreakoutDB(ctx)
		configurationVerified = readErr == nil && vlanAuthorityHash(latest) == vlanAuthorityHash(db)
		runtimeVerified = runtimeVerified && configurationVerified
		if readErr == nil {
			db = latest
		}
		return fail("persistence pending; save failed or outcome uncertain")
	}
	if !m.breakoutPersisted(p, r.After) {
		return fail("persistence pending; saved port layout does not match recorded target")
	}
	runtimeVerified = false
	if err := m.waitBreakoutRuntime(convergenceCtx, p, r.After, r.UnrelatedHash); err != nil {
		latest, _, readErr := m.readBreakoutDB(ctx)
		configurationVerified = readErr == nil && vlanAuthorityHash(latest) == vlanAuthorityHash(db)
		return fail("post-save verification failed: " + err.Error())
	}
	runtimeVerified = true
	db, _, err = m.readBreakoutDB(ctx)
	if err != nil || ctx.Err() != nil || breakoutUnrelatedHash(db, p) != r.UnrelatedHash || !reflect.DeepEqual(breakoutTarget(db, p), r.After) {
		runtimeVerified = false
		configurationVerified = false
		return fail("configuration changed during save; breakout remains pending")
	}
	r.Pending = false
	if err := storeBreakoutRecord(j, r); err != nil {
		r.Pending = true
		return fail("save acknowledged but journal completion durability uncertain; retry verification")
	}
	m.configDirty = false
	out := breakoutResult(db, p, r)
	out.RuntimeVerified, out.PersistenceVerified = true, true
	out.ConfigurationVerified = true
	return out, nil
}

func (m *SonicAgent) breakoutPersisted(p *breakoutPlatform, target vlanChangeDB) bool {
	saved, err := m.savedPortConfig()
	return err == nil && breakoutConfigMatches(saved, p, target["BREAKOUT_CFG|"+p.Port]["brkout_mode"]) == nil && reflect.DeepEqual(breakoutTarget(saved, p), target)
}
