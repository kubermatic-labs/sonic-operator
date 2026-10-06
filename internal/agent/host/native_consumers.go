// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
)

type nativeConsumer struct {
	key, path string
	container bool
}

func consumerPaths(domain string) []nativeConsumer {
	switch domain {
	case "Management":
		return []nativeConsumer{{"interfaces-generator", "/usr/bin/interfaces-config.sh", false}}
	case "ntpsec":
		return []nativeConsumer{{"ntp-generator", "/usr/bin/ntp-config.sh", false}, {"ntp-startup", "/usr/libexec/ntpsec/ntp-systemd-wrapper", false}, {"ntp-daemon", "/usr/sbin/ntpd", false}}
	case "chrony":
		return []nativeConsumer{{"ntp-generator", "/usr/bin/chrony-config.sh", false}, {"ntp-startup", "/usr/local/sbin/chronyd-starter.sh", false}, {"ntp-daemon", "/usr/sbin/chronyd", false}}
	case "snmp":
		return []nativeConsumer{{"snmp-init", "/usr/bin/docker-snmp-init.sh", true}, {"snmp-startup", "/usr/bin/start.sh", true}, {"snmp-importer", "/usr/bin/snmp_yml_to_configdb.py", true}, {"snmp-supervisor-template", "/usr/share/sonic/templates/supervisord.conf.j2", true}, {"snmp-daemon", "/usr/sbin/snmpd", true}, {"snmp-library", "/usr/lib/x86_64-linux-gnu/libnetsnmp.so.40", true}}
	}
	return nil
}
func (n *Native) verifyConsumers(ctx context.Context, p NativeProfile, domain string) error {
	consumers := consumerPaths(domain)
	if len(consumers) == 0 {
		return ErrNative
	}
	for _, c := range consumers {
		digest := p.ConsumerSHA256[c.key]
		if len(digest) != 64 {
			return ErrNative
		}
		if c.container {
			data, e := n.containerFile(ctx, c.path)
			if e != nil {
				return e
			}
			if !hashMatches(data, digest) {
				return ErrNative
			}
		} else {
			data, e := n.read(c.path)
			if e != nil || !hashMatches(data, digest) {
				return ErrNative
			}
		}
	}
	return nil
}
