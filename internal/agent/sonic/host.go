// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func (m *SonicAgent) ConfigureHostJournal(dir string) error {
	if !filepath.IsAbs(dir) {
		return host.ErrStorage
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return host.ErrStorage
	}
	m.hostJournalDir = dir
	return nil
}

type hostCASKey struct{}

func hostDatabase(db vlanChangeDB) host.Database {
	out := host.Database{}
	for key, fields := range db {
		table, row, ok := strings.Cut(key, "|")
		if ok && slices.Contains(host.HostTables, table) {
			if out[table] == nil {
				out[table] = map[string]map[string]string{}
			}
			out[table][row] = fields
		}
	}
	return out
}
func hostChanges(before, after host.Database) (vlanChangeDB, vlanChangeDB, error) {
	old, new := vlanChangeDB{}, vlanChangeDB{}
	tables := map[string]bool{}
	for t := range before {
		tables[t] = true
	}
	for t := range after {
		tables[t] = true
	}
	for t := range tables {
		rows := map[string]bool{}
		for k := range before[t] {
			rows[k] = true
		}
		for k := range after[t] {
			rows[k] = true
		}
		for row := range rows {
			a, b := before[t][row], after[t][row]
			if reflect.DeepEqual(a, b) {
				continue
			}
			allowed := (t == "NTP" && row == "global") || t == "NTP_SERVER" || t == "SNMP_COMMUNITY" || (t == "SNMP" && (row == "LOCATION" || row == "CONTACT")) || (t == "MGMT_INTERFACE" && strings.HasPrefix(row, "eth0|"))
			if !allowed {
				return nil, nil, host.ErrInvalid
			}
			if a != nil {
				old[t+"|"+row] = a
			}
			if b != nil {
				new[t+"|"+row] = b
			}
		}
	}
	return old, new, nil
}

// NewHostNative reuses the existing full-snapshot CAS and writer lock order,
// while the host protocol itself exposes only typed management/system settings.
func (m *SonicAgent) NewHostNative() *host.Native {
	return &host.Native{
		Load: func(ctx context.Context) (host.Database, error) {
			db, _, e := m.vlanChangeSnapshot(ctx)
			if e != nil {
				return nil, host.ErrNative
			}
			return hostDatabase(db), nil
		},
		CAS: func(ctx context.Context, before, after host.Database) error {
			old, next, e := hostChanges(before, after)
			if e != nil {
				return e
			}
			db, raw, e := m.vlanChangeSnapshot(ctx)
			if e != nil || !reflect.DeepEqual(hostDatabase(db), before) {
				return host.ErrConflict
			}
			if len(old) == 0 && len(next) == 0 {
				return nil
			}
			ok, e := m.casVLANChange(context.WithValue(ctx, hostCASKey{}, true), raw, old, next)
			if e != nil || !ok {
				return host.ErrConflict
			}
			return nil
		},
		Save: func(ctx context.Context) error {
			if st := m.saveConfigLocked(ctx); st != nil && st.Code != 0 {
				return host.ErrNative
			}
			return nil
		},
		WithMutation:   m.withHostMutation,
		BeforeRecovery: m.recoverHostDependencies,
	}
}
func (m *SonicAgent) withHostMutation(ctx context.Context, fn func() error) error {
	return m.withHostWriterLocks(ctx, func(locks hostWriterLocks) error {
		if locks.vlan != nil {
			if err := locks.vlan.checkPending(0); err != nil {
				return host.ErrConflict
			}
		}
		if locks.breakout != nil {
			r, e := loadBreakoutRecord(locks.breakout)
			if e != nil {
				return host.ErrStorage
			}
			if r != nil && r.Pending {
				return host.ErrConflict
			}
		}
		if locks.network != nil {
			r, e := loadNetworkJournal(locks.network)
			if e != nil {
				return host.ErrStorage
			}
			for _, record := range r.Records {
				if record.Pending != nil {
					return host.ErrConflict
				}
			}
		}
		return fn()
	})
}

type hostWriterLocks struct{ vlan, breakout, network *vlanAuthorityJournal }

func (m *SonicAgent) withHostWriterLocks(ctx context.Context, fn func(hostWriterLocks) error) error {
	for !m.configMutex.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer m.configMutex.Unlock()
	var locks hostWriterLocks
	if m.journalDir != "" {
		j, e := m.lockVLANAuthorityJournal(ctx)
		if e != nil {
			return host.ErrStorage
		}
		defer j.close()
		locks.vlan = j
	}
	if m.breakoutJournalDir != "" {
		j, e := m.lockBreakoutJournal(ctx)
		if e != nil {
			return host.ErrStorage
		}
		defer j.close()
		locks.breakout = j
	}
	if m.networkJournalDir != "" {
		j, e := m.lockNetworkJournal(ctx)
		if e != nil {
			return host.ErrStorage
		}
		defer j.close()
		locks.network = j
	}
	return fn(locks)
}
