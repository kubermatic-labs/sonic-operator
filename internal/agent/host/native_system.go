// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"encoding/csv"
	"reflect"
	"slices"
	"strings"
)

const snmpTemplate = "/usr/share/sonic/templates/snmpd.conf.j2"

func (n *Native) validateSystem(ctx context.Context, s System, p NativeProfile, db Database) error {
	if err := validateNTPImage(p, s.NTP); err != nil {
		return err
	}
	after, e := systemDatabase(db, s)
	if e != nil {
		return e
	}
	if s.NTP != nil {
		if e = n.verifyConsumers(ctx, p, p.NTPBackend); e != nil {
			return e
		}
		profile, e := n.ntpProfile(p)
		if e != nil {
			return e
		}
		candidate, e := n.render(ctx, after, profile.template, false)
		if e != nil {
			return e
		}
		f := n.Run
		if f == nil {
			f = boundedRun
		}
		if p.NTPBackend != "ntpsec" {
			if _, e = f(ctx, []string{"chronyd", "-p", "-f", "/dev/stdin"}, candidate); e != nil {
				return ErrNative
			}
		}
	}
	if s.SNMP != nil {
		if e = n.validateSNMPBootstrap(); e != nil {
			return e
		}
		if e = n.verifyConsumers(ctx, p, "snmp"); e != nil {
			return e
		}
		b, e := n.containerFile(ctx, snmpTemplate)
		if e != nil || !hashMatches(b, p.SNMPSHA256) {
			return ErrNative
		}
		if _, e = n.render(ctx, after, snmpTemplate, true); e != nil {
			return e
		}
	}
	return nil
}
func systemTables(s System) []string {
	var t []string
	if s.NTP != nil {
		t = append(t, "NTP", "NTP_SERVER")
	}
	if s.SNMP != nil {
		t = append(t, "SNMP", "SNMP_COMMUNITY")
	}
	return t
}
func (n *Native) observeSystem(ctx context.Context, q Request, db, saved Database) (Result, error) {
	out := Result{GatewayVerified: true}
	s := *q.System
	after, e := systemDatabase(db, s)
	if e != nil {
		return out, e
	}
	out.ConfigurationVerified = scopedEqual(db, after, systemTables(s)...)
	out.PersistenceVerified = scopedEqual(saved, after, systemTables(s)...)
	p, e := n.profile(ctx, "System")
	if e != nil {
		return out, e
	}
	out.RuntimeVerified = true
	if s.NTP != nil {
		profile, e := n.ntpProfile(p)
		if e != nil {
			return out, e
		}
		if e = n.verifyConsumers(ctx, p, p.NTPBackend); e != nil {
			return out, e
		}
		generated, e := n.render(ctx, after, profile.template, false)
		if e != nil {
			return out, e
		}
		installed, e := n.read(profile.output)
		equal := e == nil && bytes.Equal(generated, installed)
		out.PersistenceVerified = out.PersistenceVerified && equal
		args := []string{"chronyc", "-c", "-N", "sources"}
		matches := ntpSourcesMatch
		if p.NTPBackend == "ntpsec" {
			args = []string{"ntpq", "-pn"}
			matches = ntpsecSourcesMatch
		}
		b, e := n.run(ctx, args...)
		out.RuntimeVerified = out.RuntimeVerified && equal && e == nil && matches(s.NTP.Servers, b)
		b, e = n.run(ctx, "systemctl", "is-active", profile.service)
		out.RuntimeVerified = out.RuntimeVerified && e == nil && strings.TrimSpace(string(b)) == "active"
		out.RuntimeVerified = out.RuntimeVerified && n.daemonLoaded(ctx, p.NTPBackend, generated, q, p)
	}
	if s.SNMP != nil {
		if e = n.verifyConsumers(ctx, p, "snmp"); e != nil {
			return out, e
		}
		template, e := n.containerFile(ctx, snmpTemplate)
		if e != nil || !hashMatches(template, p.SNMPSHA256) {
			return out, ErrNative
		}
		state, e := n.snmpContainer(ctx)
		if e != nil {
			return out, e
		}
		if !state.State.Running {
			bootstrap, e := n.read(snmpBootstrapPath)
			out.PersistenceVerified = out.PersistenceVerified && e == nil && snmpBootstrapMatches(bootstrap, *s.SNMP)
			out.RuntimeVerified = false
			return out, nil
		}
		generated, e := n.render(ctx, after, snmpTemplate, true)
		if e != nil {
			return out, e
		}
		installed, e := n.run(ctx, "docker", "exec", "snmp", "cat", "/etc/snmp/snmpd.conf")
		equal := e == nil && bytes.Equal(generated, installed)
		out.PersistenceVerified = out.PersistenceVerified && equal
		supervisor, e := n.render(ctx, after, "/usr/share/sonic/templates/supervisord.conf.j2", true)
		if e != nil {
			return out, e
		}
		installedSupervisor, e := n.run(ctx, "docker", "exec", "snmp", "cat", "/etc/supervisor/conf.d/supervisord.conf")
		equal = equal && e == nil && bytes.Equal(supervisor, installedSupervisor)
		bootstrap, e := n.read(snmpBootstrapPath)
		out.PersistenceVerified = out.PersistenceVerified && e == nil && snmpBootstrapMatches(bootstrap, *s.SNMP)
		// Protocol GET proves the running agent loaded the credential and settings;
		// neither Redis equality nor process liveness alone establishes this.
		out.RuntimeVerified = out.RuntimeVerified && equal && n.daemonLoaded(ctx, "snmp", generated, q, p)
		if s.SNMP.Community != "" {
			verify := func() error { return probeSNMP(ctx, *s.SNMP, "127.0.0.1:161") }
			if n.SNMPExchange != nil {
				verify = func() error { return probeSNMPExchange(ctx, *s.SNMP, n.SNMPExchange) }
			}
			out.RuntimeVerified = out.RuntimeVerified && verify() == nil
		}
	}
	return out, nil
}
func ntpSourcesMatch(want []string, data []byte) bool {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	rows, e := r.ReadAll()
	if e != nil {
		return false
	}
	var got []string
	for _, row := range rows {
		if len(row) < 3 {
			return false
		}
		got = append(got, row[2])
	}
	want = slices.Clone(want)
	slices.Sort(want)
	slices.Sort(got)
	return reflect.DeepEqual(want, got) || (len(want) == 0 && len(got) == 0)
}
func (n *Native) ApplySystem(ctx context.Context, q Request) error {
	if ValidateRequest(q) != nil || q.System == nil {
		return ErrInvalid
	}
	s := *q.System
	return n.mutate(ctx, func() error {
		if s.SNMP != nil {
			if err := n.validateSNMPBootstrap(); err != nil {
				return err
			}
		}
		db, e := n.Load(ctx)
		if e != nil {
			return ErrNative
		}
		after, e := systemDatabase(db, s)
		if e != nil {
			return e
		}
		p, e := n.profile(ctx, "System")
		if e != nil {
			return e
		}
		if e = n.validateSystem(ctx, s, p, db); e != nil {
			return e
		}
		var chrony []byte
		var snmp []byte
		var ntpProfile ntpNativeProfile
		if s.NTP != nil {
			ntpProfile, e = n.ntpProfile(p)
			if e != nil {
				return e
			}
			chrony, e = n.render(ctx, after, ntpProfile.template, false)
			if e != nil {
				return e
			}
		}
		if s.SNMP != nil {
			snmp, e = n.render(ctx, after, snmpTemplate, true)
			if e != nil {
				return e
			}
		}
		if e = n.CAS(ctx, db, after); e != nil {
			return e
		}
		if s.NTP != nil {
			if e = n.write(ntpProfile.output, chrony, 0644); e != nil {
				return e
			}
			if e = n.activateDaemon(ctx, q, p, p.NTPBackend, ntpProfile.service, chrony); e != nil {
				return e
			}
		}
		if s.SNMP != nil {
			bootstrap, e := snmpBootstrap(*s.SNMP)
			if e != nil {
				return e
			}
			if e = n.write(snmpBootstrapPath, bootstrap, 0600); e != nil {
				return e
			}
			if e = n.activateDaemon(ctx, q, p, "snmp", "snmp.service", snmp); e != nil {
				return e
			}
		}
		if n.Save(ctx) != nil {
			return ErrNative
		}
		return nil
	})
}
