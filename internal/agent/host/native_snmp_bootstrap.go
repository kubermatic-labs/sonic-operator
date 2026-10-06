// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const snmpBootstrapPath = "/etc/sonic/snmp.yml"

// The installed /usr/bin/start.sh invokes snmp_yml_to_configdb.py on every
// container start. This private generating input must converge alongside Redis;
// otherwise a retired community is reintroduced after a service restart/reboot.
type snmpStartup struct {
	Location      string   `yaml:"snmp_location" json:"snmp_location"`
	ROCommunity   string   `yaml:"snmp_rocommunity" json:"snmp_rocommunity,omitempty"`
	ROCommunities []string `yaml:"snmp_rocommunities" json:"snmp_rocommunities,omitempty"`
	RWCommunity   string   `yaml:"snmp_rwcommunity" json:"snmp_rwcommunity,omitempty"`
	RWCommunities []string `yaml:"snmp_rwcommunities" json:"snmp_rwcommunities,omitempty"`
}

func snmpBootstrap(s SNMP) ([]byte, error) {
	if ValidateSystem(System{SNMP: &s}) != nil {
		return nil, ErrInvalid
	}
	// JSON is accepted by the installed YAML FullLoader and avoids unquoted
	// credential metacharacters. The bytes only go to the private native file.
	return json.Marshal(snmpStartup{Location: s.Location, ROCommunity: string(s.Community)})
}
func snmpBootstrapMatches(data []byte, s SNMP) bool {
	v, err := decodeSNMPBootstrap(data)
	if err != nil {
		return false
	}
	if v.Location != s.Location || v.RWCommunity != "" || len(v.RWCommunities) > 0 {
		return false
	}
	communities := append([]string{}, v.ROCommunities...)
	if v.ROCommunity != "" {
		communities = append(communities, v.ROCommunity)
	}
	if s.Community == "" {
		return len(communities) == 0
	}
	return len(communities) == 1 && communities[0] == string(s.Community)
}
func decodeSNMPBootstrap(data []byte) (snmpStartup, error) {
	var v snmpStartup
	if len(data) > 64<<10 {
		return v, ErrNative
	}
	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return v, ErrNative
	}
	// The installed Python FullLoader uses YAML 1.1 scalar resolution. Do not
	// mistake numbers, booleans, null or custom tags for string boot inputs.
	text := func(node *yaml.Node) bool {
		return node.Kind == yaml.ScalarNode && node.Tag == "!!str" && (node.Style != 0 || !slices.Contains([]string{"yes", "no", "on", "off"}, strings.ToLower(node.Value)))
	}
	fields := document.Content[0].Content
	for i := 0; i < len(fields); i += 2 {
		if !text(fields[i]) {
			return v, ErrNative
		}
		value := fields[i+1]
		if fields[i].Value == "snmp_rocommunities" || fields[i].Value == "snmp_rwcommunities" {
			if value.Kind != yaml.SequenceNode {
				return v, ErrNative
			}
			for _, item := range value.Content {
				if !text(item) {
					return v, ErrNative
				}
			}
		} else if !text(value) {
			return v, ErrNative
		}
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if d.Decode(&v) != nil {
		return v, ErrNative
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return v, ErrNative
	}
	return v, nil
}
func (n *Native) validateSNMPBootstrap() error {
	b, e := n.read(snmpBootstrapPath)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return ErrNative
	}
	v, e := decodeSNMPBootstrap(b)
	if e != nil || v.RWCommunity != "" || len(v.RWCommunities) > 0 {
		return ErrNative
	}
	return nil
}
