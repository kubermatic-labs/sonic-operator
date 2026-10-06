// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"maps"
	"regexp"
	"strings"
)

var evpnPolicyName = regexp.MustCompile(`^SOEV_[a-f0-9]{20}_[IO]$`)

// Reconstruct only the exact supported policy graph. Matching reserved names
// alone is insufficient: definitions, matches, deny and attachments must agree.
func evpnConfiguredPeerPolicy(db vlanChangeDB, peer string) (*evpnPeerPolicy, error) {
	row := db["BGP_NEIGHBOR_AF|default|"+peer+"|"+evpnAF]
	in, out := row["route_map_in@"], row["route_map_out@"]
	transit := row["unchanged_nexthop"] == "true"
	count := 4
	if transit {
		count = 5
	}
	if len(row) != count || !evpnPolicyName.MatchString(in) || !evpnPolicyName.MatchString(out) || !strings.HasSuffix(in, "_I") || out != strings.TrimSuffix(in, "_I")+"_O" || row["send_community"] != "extended" || (row["admin_status"] != "up" && row["admin_status"] != "down") {
		return nil, fmt.Errorf("incomplete EVPN AF policy")
	}
	p := &evpnPeerPolicy{In: in, Out: out, Transit: transit, Rows: vlanChangeDB{}}
	for _, name := range []string{in, out} {
		set := db["EXTENDED_COMMUNITY_SET|"+name]
		if len(set) != 3 || set["set_type"] != "STANDARD" || set["match_action"] != "ANY" {
			return nil, fmt.Errorf("invalid EVPN RT set")
		}
		var targets []string
		for _, member := range strings.Split(set["community_member@"], ",") {
			rt, ok := strings.CutPrefix(member, "route-target:")
			if !ok {
				return nil, fmt.Errorf("non-RT EVPN policy member")
			}
			targets = append(targets, rt)
		}
		var err error
		targets, err = evpnRTs(targets)
		if err != nil {
			return nil, err
		}
		if name == in {
			p.Import = targets
		} else {
			p.Export = targets
		}
		want := map[string]map[string]string{"10": {"route_operation": "permit", "match_ext_community": name}, "65535": {"route_operation": "deny"}}
		for sequence, fields := range want {
			if !maps.Equal(db["ROUTE_MAP|"+name+"|"+sequence], fields) {
				return nil, fmt.Errorf("EVPN filter lacks exact match/default deny")
			}
		}
		for key := range db {
			if strings.HasPrefix(key, "ROUTE_MAP|"+name+"|") && want[strings.TrimPrefix(key, "ROUTE_MAP|"+name+"|")] == nil {
				return nil, fmt.Errorf("extra EVPN route-map sequence")
			}
		}
	}
	return p, nil
}

func evpnGlobalConfigValid(row map[string]string) bool {
	return maps.Equal(row, evpnGlobalFields(false)) || maps.Equal(row, evpnGlobalFields(true))
}
