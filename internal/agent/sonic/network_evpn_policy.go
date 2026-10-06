// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

type evpnPeerPolicy struct {
	Transit        bool
	In, Out        string
	Import, Export []string
	Rows           vlanChangeDB
}

func evpnBuildPeerPolicy(owner, peer string, imports, exports []string) (*evpnPeerPolicy, error) {
	if owner == "" || len(owner) > 256 {
		return nil, fmt.Errorf("EVPN policy requires bounded owner UID")
	}
	ip, err := routingAddress(peer, nil)
	if err != nil || ip.String() != peer {
		return nil, fmt.Errorf("EVPN policy requires canonical peer address")
	}
	imports, err = evpnRTs(imports)
	if err != nil {
		return nil, err
	}
	exports, err = evpnRTs(exports)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(owner + "\x00" + peer))
	p := &evpnPeerPolicy{In: fmt.Sprintf("SOEV_%x_I", hash[:10]), Out: fmt.Sprintf("SOEV_%x_O", hash[:10]), Import: imports, Export: exports, Rows: vlanChangeDB{}}
	for _, direction := range []struct {
		name    string
		targets []string
	}{{p.In, imports}, {p.Out, exports}} {
		members := make([]string, len(direction.targets))
		for i, rt := range direction.targets {
			members[i] = "route-target:" + rt
		}
		p.Rows["EXTENDED_COMMUNITY_SET|"+direction.name] = map[string]string{"set_type": "STANDARD", "match_action": "ANY", "community_member@": strings.Join(members, ",")}
		p.Rows["ROUTE_MAP|"+direction.name+"|10"] = map[string]string{"route_operation": "permit", "match_ext_community": direction.name}
		p.Rows["ROUTE_MAP|"+direction.name+"|65535"] = map[string]string{"route_operation": "deny"}
	}
	return p, nil
}
