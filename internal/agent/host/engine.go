// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"
)

var (
	ErrStorage      = errors.New("host recovery storage unavailable")
	ErrConflict     = errors.New("host ownership or pending transaction conflict")
	ErrNative       = errors.New("native host configuration could not be verified")
	ErrConfirmation = errors.New("fresh connection verification required before deadline")
)

type Backend interface {
	Exclusive(context.Context, func(context.Context) error) error
	RecoverDependencies(context.Context) error
	Observe(context.Context, Request) (Result, error)
	Snapshot(context.Context) (Snapshot, error)
	Validate(context.Context, Request) error
	WatchdogReady(context.Context) error
	ApplyManagement(context.Context, Snapshot, Management) error
	RestoreManagement(context.Context, RecoveryScope) error
	ApplySystem(context.Context, Request) error
}
type proof struct{ transaction, connection, challenge string }
type Engine struct {
	dir     string
	backend Backend
	mu      sync.Mutex
	now     func() time.Time
	bootNow func() (bootClock, error)
	proof   proof
	syncDir func(*os.File) error
}

func NewEngine(dir string, b Backend) (*Engine, error) {
	if b == nil || !filepath.IsAbs(dir) {
		return nil, ErrStorage
	}
	info, err := os.Lstat(dir)
	if err != nil || secureFile(info, true) != nil {
		return nil, ErrStorage
	}
	if configurable, ok := b.(interface{ ConfigureState(string) error }); ok {
		if err := configurable.ConfigureState(dir); err != nil {
			return nil, err
		}
	}
	return &Engine{dir: dir, backend: b, now: time.Now, bootNow: readBootClock}, nil
}
func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}
func managementEqual(a, b Management) bool {
	a.Addresses = slices.Clone(a.Addresses)
	b.Addresses = slices.Clone(b.Addresses)
	slices.SortFunc(a.Addresses, func(a, b Address) int {
		if a.Prefix < b.Prefix {
			return -1
		}
		if a.Prefix > b.Prefix {
			return 1
		}
		return 0
	})
	slices.SortFunc(b.Addresses, func(a, b Address) int {
		if a.Prefix < b.Prefix {
			return -1
		}
		if a.Prefix > b.Prefix {
			return 1
		}
		return 0
	})
	return reflect.DeepEqual(a, b)
}
func requestClaim(q Request) *claim {
	return &claim{Owner: q.Owner, Target: q.Target, Revision: q.Revision}
}
func ownerMatches(c *claim, q Request) bool {
	return c == nil || (c.Owner == q.Owner && c.Target == q.Target)
}
func pendingMatches(p *transaction, q Request) bool {
	return q.Kind == "Management" && p.Claim == *requestClaim(q) && q.Management != nil && managementEqual(p.Candidate, *q.Management)
}
func (e *Engine) expired(p *transaction) bool {
	if p.RollbackRequired {
		return true
	}
	if p.BootID != "" {
		clock, err := e.bootNow()
		return err != nil || clock.ID != p.BootID || clock.Seconds >= p.DeadlineUptime
	}
	now := e.now()
	return !now.Before(p.Deadline) || now.Before(p.Created)
}

func (e *Engine) observe(ctx context.Context, q Request, r *record, conn string) (Result, error) {
	out, err := e.backend.Observe(ctx, q)
	if err != nil {
		return out, ErrNative
	}
	out.Recovery = "Idle"
	c := r.System
	if q.Kind == "Management" {
		c = r.Management
	}
	if c != nil {
		out.Owner = c.Owner
	}
	if q.Kind == "Management" && r.Pending != nil {
		p := r.Pending
		out.Recovery = "Pending"
		out.Transaction = p.ID
		if e.expired(p) {
			out.Recovery = "RollbackRequired"
		}
		if pendingMatches(p, q) && !e.expired(p) && conn != "" && conn != p.Connection && out.ConfigurationVerified && out.RuntimeVerified && out.PersistenceVerified && out.GatewayVerified {
			e.proof = proof{p.ID, conn, randomID()}
			out.Challenge = e.proof.challenge
		}
	}
	if q.Kind == "Management" && r.Pending == nil && r.RolledBack != nil && *r.RolledBack == *requestClaim(q) {
		out.Recovery = "RolledBack"
	}
	return out, nil
}
func (e *Engine) Get(ctx context.Context, q Request, conn string) (out Result, err error) {
	if ValidateRequest(q) != nil {
		return out, ErrInvalid
	}
	err = e.withRecord(ctx, func(r *record) error { var er error; out, er = e.observe(ctx, q, r, conn); return er })
	return
}
func (e *Engine) Ensure(ctx context.Context, q Request, conn string) (out Result, err error) {
	if ValidateRequest(q) != nil || conn == "" {
		return out, ErrInvalid
	}
	err = e.backend.Exclusive(ctx, func(locked context.Context) error {
		ctx = locked
		return e.withRecord(ctx, func(r *record) error {
			c := r.System
			if q.Kind == "Management" {
				c = r.Management
			}
			if !ownerMatches(c, q) {
				return ErrConflict
			}
			if q.Kind == "Management" && r.RolledBack != nil && *r.RolledBack == *requestClaim(q) {
				return ErrConflict
			}
			// Host mutations share the management connection; freeze all host writes
			// until its pending transaction is independently confirmed or recovered.
			if r.Pending != nil {
				if !pendingMatches(r.Pending, q) {
					return ErrConflict
				}
				var er error
				out, er = e.observe(ctx, q, r, conn)
				return er
			}
			current, er := e.backend.Observe(ctx, q)
			if er != nil {
				return ErrNative
			}
			if current.ConfigurationVerified && current.RuntimeVerified && current.PersistenceVerified {
				if q.Kind == "Management" {
					r.Management = requestClaim(q)
				} else {
					r.System = requestClaim(q)
				}
				if er = e.save(r); er != nil {
					return er
				}
				out = current
				out.Owner = q.Owner
				out.Recovery = "Idle"
				return nil
			}
			if e.backend.Validate(ctx, q) != nil {
				return ErrNative
			}
			if q.Kind == "System" {
				r.System = requestClaim(q)
				if er = e.save(r); er != nil {
					return er
				}
				if e.backend.ApplySystem(ctx, q) != nil {
					return ErrNative
				}
				out, er = e.observe(ctx, q, r, conn)
				return er
			}
			if e.backend.WatchdogReady(ctx) != nil {
				return ErrNative
			}
			before, er := e.backend.Snapshot(ctx)
			if er != nil {
				return ErrNative
			}
			old := q
			old.Management = &before.Management
			baseline, er := e.backend.Observe(ctx, old)
			repairRuntime := current.ConfigurationVerified && current.PersistenceVerified
			if er != nil || !baseline.ConfigurationVerified || (!baseline.RuntimeVerified && !repairRuntime) {
				return ErrNative
			}
			recoveryBefore := before
			if repairRuntime && q.Management.MAC != "" {
				recoveryBefore.ActiveMAC = q.Management.MAC
			}
			now := e.now()
			clock, er := e.bootNow()
			if er != nil {
				return ErrStorage
			}
			r.Management = requestClaim(q)
			r.Pending = &transaction{ID: randomID(), Claim: *requestClaim(q), Before: recoveryBefore, Candidate: *q.Management, ObservedActiveMAC: before.ActiveMAC, Created: now, Deadline: now.Add(time.Duration(q.RollbackSeconds) * time.Second), Connection: conn}
			r.Pending.BootID, r.Pending.DeadlineUptime = clock.ID, clock.Seconds+float64(q.RollbackSeconds)
			if er = e.save(r); er != nil {
				return er
			}
			applyCtx, cancelApply := context.WithTimeout(ctx, time.Duration(q.RollbackSeconds-5)*time.Second)
			defer cancelApply()
			if e.backend.ApplyManagement(applyCtx, before, *q.Management) != nil {
				r.Pending.RollbackRequired = true
				if er = e.save(r); er != nil {
					return er
				}
				// Detach the lost RPC while retaining the exclusion capability held
				// by this callback. Background would attempt to relock our own mutex.
				recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
				defer cancel()
				if restoreErr := e.restore(recovery, r); restoreErr != nil {
					return errors.Join(ErrNative, restoreErr)
				}
				return ErrNative
			}
			out, er = e.observe(applyCtx, q, r, conn)
			return er
		})
	})
	return
}

func (e *Engine) Confirm(ctx context.Context, c Confirmation, conn string) (out Result, err error) {
	err = e.withRecord(ctx, func(r *record) error {
		p := r.Pending
		if p == nil || p.Claim.Owner != c.Owner || p.Claim.Target != c.Target || p.ID != c.Transaction || e.expired(p) || e.proof != (proof{c.Transaction, conn, c.Challenge}) || c.Challenge == "" || conn == p.Connection {
			return ErrConfirmation
		}
		q := Request{Kind: "Management", Owner: c.Owner, Target: c.Target, Revision: p.Claim.Revision, Management: &p.Candidate, RollbackSeconds: 60}
		verified, er := e.backend.Observe(ctx, q)
		if er != nil || !verified.ConfigurationVerified || !verified.RuntimeVerified || !verified.PersistenceVerified || !verified.GatewayVerified {
			return ErrNative
		}
		// Recheck after potentially slow native probes.
		if e.expired(p) {
			return ErrConfirmation
		}
		r.Pending = nil
		if er = e.save(r); er != nil {
			return er
		}
		e.proof = proof{}
		out = verified
		out.Owner = c.Owner
		out.Recovery = "Confirmed"
		return nil
	})
	return
}
