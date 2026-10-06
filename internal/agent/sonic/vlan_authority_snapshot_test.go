// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"maps"
	"reflect"
	"strings"
	"testing"
)

func vlanAuthorityMetadataFixture() vlanChangeDB {
	return vlanChangeDB{
		"PORT|Ethernet0":            {"alias": "etp1", "speed": "100000"},
		"PORT|Ethernet4":            {"alias": "etp2", "speed": "100000"},
		"LOGGER|SAI_API_VLAN":       {"LOGLEVEL": "SAI_LOG_LEVEL_NOTICE", "LOGOUTPUT": "SYSLOG"},
		"LOGGER|vlanmgrd":           {"LOGLEVEL": "NOTICE", "LOGOUTPUT": "SYSLOG"},
		"LOGGER|xcvrd":              {"LOGLEVEL": "NOTICE", "require_manual_refresh": "true"},
		"LOGGER|CmisManagerTask":    {"LOGLEVEL": "NOTICE", "require_manual_refresh": "true"},
		"LOGGER|DomInfoUpdateTask":  {"LOGLEVEL": "NOTICE", "require_manual_refresh": "true"},
		"LOGGER|SfpStateUpdateTask": {"LOGLEVEL": "NOTICE", "require_manual_refresh": "true"},
		"BREAKOUT_CFG|Ethernet0":    {"brkout_mode": "1x100G[40G]"},
		"BREAKOUT_CFG|Ethernet4":    {"brkout_mode": "1x100G[40G]"},
	}
}

func vlanAuthorityUnsafeMetadataCases() []struct {
	name, key string
	fields    map[string]string
} {
	cases := []struct {
		name, key string
		fields    map[string]string
	}{
		{"logger unknown field", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "NOTICE", "future": "opaque"}},
		{"logger VLAN reference", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "NOTICE", "vlans": "all"}},
		{"logger port reference", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "NOTICE", "ports": "Ethernet0"}},
		{"logger missing level", "LOGGER|vlanmgrd", map[string]string{"LOGOUTPUT": "SYSLOG"}},
		{"logger invalid level", "LOGGER|orchagent", map[string]string{"LOGLEVEL": "invalid"}},
		{"logger lowercase level", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "notice"}},
		{"logger level reference", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "Vlan100"}},
		{"logger invalid output", "LOGGER|orchagent", map[string]string{"LOGLEVEL": "NOTICE", "LOGOUTPUT": "FILE"}},
		{"logger output reference", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "NOTICE", "LOGOUTPUT": "Ethernet0"}},
		{"logger empty output", "LOGGER|vlanmgrd", map[string]string{"LOGLEVEL": "NOTICE", "LOGOUTPUT": ""}},
		{"logger missing separator", "LOGGER", map[string]string{"LOGLEVEL": "NOTICE"}},
		{"logger empty component", "LOGGER|", map[string]string{"LOGLEVEL": "NOTICE"}},
		{"logger extra key component", "LOGGER|vlanmgrd|extra", map[string]string{"LOGLEVEL": "NOTICE"}},
		{"logger whitespace component", "LOGGER|vlanmgrd ", map[string]string{"LOGLEVEL": "NOTICE"}},
		{"logger refresh field case", "LOGGER|xcvrd", map[string]string{"LOGLEVEL": "NOTICE", "REQUIRE_MANUAL_REFRESH": "true"}},
		{"logger refresh field suffix", "LOGGER|xcvrd", map[string]string{"LOGLEVEL": "NOTICE", "require_manual_refresh_extra": "true"}},
		{"breakout unknown field", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100G", "future": "opaque"}},
		{"breakout VLAN reference", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100G", "vlan": "all"}},
		{"breakout missing mode", "BREAKOUT_CFG|Ethernet0", map[string]string{"NULL": "NULL"}},
		{"breakout empty mode", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": ""}},
		{"breakout noncanonical port", "BREAKOUT_CFG|Ethernet00", map[string]string{"brkout_mode": "1x100G"}},
		{"breakout LAG", "BREAKOUT_CFG|PortChannel1", map[string]string{"brkout_mode": "1x100G"}},
		{"breakout extra key component", "BREAKOUT_CFG|Ethernet0|extra", map[string]string{"brkout_mode": "1x100G"}},
		{"breakout missing separator", "BREAKOUT_CFG", map[string]string{"brkout_mode": "1x100G"}},
		{"breakout port reference", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "Ethernet4"}},
		{"breakout trailing reference", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100G+Vlan100"}},
		{"breakout trailing junk", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100Gjunk"}},
		{"breakout trailing newline", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100G\n"}},
		{"breakout zero ports", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "0x100G"}},
		{"breakout empty speed list", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100G[]"}},
		{"breakout trailing comma", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": "1x100G[40G,]"}},
		{"breakout too long", "BREAKOUT_CFG|Ethernet0", map[string]string{"brkout_mode": strings.Repeat("1x100G+", 10) + "1x100G"}},
		{"unknown VLAN table", "FUTURE_VLAN|selector", map[string]string{"range": "all"}},
		{"logger lookalike table", "LOGGER_EXTRA|vlanmgrd", map[string]string{"LOGLEVEL": "NOTICE"}},
		{"breakout lookalike table", "BREAKOUT_CFG_EXTRA|Ethernet0", map[string]string{"brkout_mode": "1x100G"}},
		{"routed port", "INTERFACE|Ethernet0|192.0.2.1/24", map[string]string{"NULL": "NULL"}},
		{"LAG member", "PORTCHANNEL_MEMBER|PortChannel1|Ethernet0", map[string]string{"NULL": "NULL"}},
		{"unknown port table", "MYSTERY|Ethernet0", map[string]string{"NULL": "NULL"}},
	}
	for _, value := range []string{"", "True", "False", "TRUE", "FALSE", "1", "0", "yes", " true", "false\n", "Vlan100", "Ethernet0"} {
		cases = append(cases, struct {
			name, key string
			fields    map[string]string
		}{"logger invalid refresh " + value, "LOGGER|xcvrd", map[string]string{"LOGLEVEL": "NOTICE", "require_manual_refresh": value}})
	}
	return cases
}

func TestVLANAuthorityOperationalMetadata(t *testing.T) {
	t.Parallel()
	target := vlanChangeDB{
		"VLAN|Vlan100":                  {"vlanid": "100"},
		"VLAN_MEMBER|Vlan100|Ethernet0": {"tagging_mode": "untagged"},
		"VLAN_MEMBER|Vlan100|Ethernet4": {"tagging_mode": "tagged"},
	}
	for _, level := range []string{"EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "SAI_LOG_LEVEL_CRITICAL", "SAI_LOG_LEVEL_ERROR", "SAI_LOG_LEVEL_WARN", "SAI_LOG_LEVEL_NOTICE", "SAI_LOG_LEVEL_INFO", "SAI_LOG_LEVEL_DEBUG"} {
		for _, output := range []string{"", "SYSLOG", "STDOUT", "STDERR"} {
			t.Run(level+"/"+output, func(t *testing.T) {
				db := vlanAuthorityMetadataFixture()
				fields := map[string]string{"LOGLEVEL": level}
				if output != "" {
					fields["LOGOUTPUT"] = output
				}
				db["LOGGER|vlanmgrd"] = fields
				before := maps.Clone(db)
				if err := vlanAuthoritySafe(db, 100, target); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(db, before) {
					t.Fatal("validation removed metadata from snapshot")
				}
			})
		}
	}
	for _, mode := range []string{"1x10G", "1x100G[40G]", "4x25G[10G]", "2x25G(2)+1x50G(2)", "1x50G(2)+2x25G(2)", "1x100000[40000,25000]"} {
		t.Run(mode, func(t *testing.T) {
			db := vlanAuthorityMetadataFixture()
			db["BREAKOUT_CFG|Ethernet0"]["brkout_mode"] = mode
			// Breakout parents need not exist in PORT during dynamic breakout.
			db["BREAKOUT_CFG|Ethernet8"] = map[string]string{"brkout_mode": mode}
			if err := vlanAuthoritySafe(db, 100, target); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, value := range []string{"absent", "true", "false"} {
		t.Run("manual refresh/"+value, func(t *testing.T) {
			db := vlanAuthorityMetadataFixture()
			for _, name := range []string{"xcvrd", "CmisManagerTask", "DomInfoUpdateTask", "SfpStateUpdateTask"} {
				fields := db["LOGGER|"+name]
				if value == "absent" {
					delete(fields, "require_manual_refresh")
				} else {
					fields["require_manual_refresh"] = value
				}
			}
			if err := vlanAuthoritySafe(db, 100, target); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range vlanAuthorityUnsafeMetadataCases() {
		t.Run(tc.name, func(t *testing.T) {
			db := vlanAuthorityMetadataFixture()
			db[tc.key] = tc.fields
			if err := vlanAuthoritySafe(db, 100, target); err == nil {
				t.Fatal("unsafe metadata or dependency accepted")
			}
		})
	}
}
