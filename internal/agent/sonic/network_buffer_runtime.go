// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
)

func bufferPlan(identity string, desired vlanChangeDB) *networkPlan {
	p := &networkPlan{Identity: identity, Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		if p.BufferProof != nil {
			return bufferRepairPreflight(ctx, qosRedisRead{m}, p.BufferProof)
		}
		proof, err := bufferDiscover(ctx, qosRedisRead{m}, desired)
		if err != nil {
			return err
		}
		p.BufferProof = proof
		return nil
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		p.BufferRepairEligible = false
		if p.BufferProof == nil {
			return bufferObserve(ctx, qosRedisRead{m}, desired)
		}
		err := bufferVerify(ctx, qosRedisRead{m}, p.BufferProof, false)
		var difference *bufferDifference
		if errors.As(err, &difference) {
			if preflightErr := bufferRepairPreflight(ctx, qosRedisRead{m}, p.BufferProof); preflightErr != nil {
				return bufferEvidence(p.BufferProof, preflightErr)
			}
			p.BufferRepairEligible = true
			_, raw, _ := bufferEvidence(p.BufferProof, err)
			return false, raw, nil
		}
		return bufferEvidence(p.BufferProof, err)
	}
	return p
}

func bufferRepairPreflight(ctx context.Context, read qosRead, p *bufferNativeProof) error {
	if err := bufferVerify(ctx, read, p, true); err != nil {
		return err
	}
	for _, check := range p.Checks {
		if (check.DB != "CONFIG_DB" && check.DB != "APPL_DB") || len(check.RepairFields) == 0 {
			continue
		}
		row, err := read.hash(ctx, check.DB, check.Key)
		if err != nil {
			return err
		}
		for _, field := range check.RepairFields {
			if _, ok := row[field]; !ok {
				return fmt.Errorf("deleted owned buffer fields require qualified native DEL cancellation/counter lifecycle recovery; SET restoration is unavailable")
			}
		}
	}
	return bufferBindingReapplyGuard(ctx, read, p)
}

// BufferOrch::processQueue/processPriorityGroup return early when the cached
// profile name is unchanged. A CONFIG_DB SET can restore configuration drift,
// but cannot force SAI repair of a binding changed solely outside that consumer.
func bufferBindingReapplyGuard(ctx context.Context, read qosRead, p *bufferNativeProof) error {
	for key, fields := range p.Desired {
		if !strings.HasPrefix(key, "BUFFER_PG|") && !strings.HasPrefix(key, "BUFFER_QUEUE|") {
			continue
		}
		row, err := read.hash(ctx, "CONFIG_DB", key)
		if err != nil {
			return err
		}
		if !networkSubset(vlanChangeDB{key: row}, vlanChangeDB{key: fields}) {
			continue
		}
		for _, check := range p.Checks {
			if check.DB != "ASIC_DB" {
				continue
			}
			for _, field := range check.RepairFields {
				if field != "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE" && field != "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID" {
					continue
				}
				attrs, err := read.hash(ctx, check.DB, check.Key)
				if err != nil {
					return err
				}
				if attrs[field] != check.Fields[field] {
					return fmt.Errorf("native BufferOrch deduplicates unchanged PG/queue profile names; out-of-band binding drift requires a qualified consumer repair capability")
				}
			}
		}
	}
	return nil
}

// Require independent producer identity/lifecycle acknowledgement in addition
// to the existing graph. The inspected SONiC cannot provide that acknowledgement.
func bufferObserve(ctx context.Context, read qosRead, desired vlanChangeDB) (bool, json.RawMessage, error) {
	proof, err := bufferDiscover(ctx, read, desired)
	return bufferEvidence(proof, err)
}

func bufferEvidence(proof *bufferNativeProof, err error) (bool, json.RawMessage, error) {
	data := map[string]any{"applied": err == nil, "source": "independent consumer identity/lifecycle plus COUNTERS topology, ASIC attributes and VIDTORID"}
	if proof != nil {
		data["nativeFingerprint"] = proof.Fingerprint
	}
	if err != nil {
		data["reason"] = err.Error()
	}
	raw, _ := json.Marshal(data)
	return err == nil, raw, err
}

func bufferRecordProof(record *networkRecord) *bufferNativeProof {
	if record == nil {
		return nil
	}
	if record.Pending != nil && record.Pending.BufferProof != nil {
		return record.Pending.BufferProof
	}
	return record.BufferProof
}

// Restore only journal-qualified fields in the planner's read-only working copy.
// The actual snapshot/raw CAS still sees the drift; dependencies are untouched.
func bufferPlanningDB(db vlanChangeDB, record *networkRecord) vlanChangeDB {
	proof := bufferRecordProof(record)
	if proof == nil {
		return db
	}
	out := maps.Clone(db)
	for key, fields := range proof.Desired {
		row := maps.Clone(db[key])
		if row == nil {
			row = map[string]string{}
		}
		maps.Copy(row, fields)
		out[key] = row
	}
	return out
}

func bufferAttachProof(p *networkPlan, record *networkRecord) error {
	proof := bufferRecordProof(record)
	if proof == nil {
		return nil
	}
	if p.Preflight == nil || p.Runtime == nil {
		return fmt.Errorf("native buffer qualification callbacks unavailable")
	}
	if !reflect.DeepEqual(p.Desired, proof.Desired) {
		return fmt.Errorf("buffer intent differs from the native-qualified adopted values")
	}
	if err := proof.validate(p.Desired); err != nil {
		return err
	}
	p.BufferProof = proof
	return nil
}
