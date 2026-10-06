// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
)

// intfmgr publishes INTF_TABLE even when its kernel address command fails.
// Verify actual addresses independently; operstate UNKNOWN is normal for dummy
// loopbacks and is not a readiness failure. Additional unowned addresses survive.
func loopbackKernelAddresses(ctx context.Context, name string, addresses []string, run lagL3CommandReader) (bool, error) {
	data, err := run(ctx, "ip", "-j", "address", "show", "dev", name)
	if err != nil {
		return false, err
	}
	var links []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
			Tentative bool   `json:"tentative"`
			DADFailed bool   `json:"dadfailed"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(data, &links) != nil || links == nil {
		return false, fmt.Errorf("invalid loopback kernel address JSON")
	}
	if len(links) != 1 || links[0].Name != name {
		return false, nil
	}
	found := map[string]bool{}
	for _, a := range links[0].Addresses {
		ip, err := netip.ParseAddr(a.Local)
		if err != nil || ip.Is4In6() || a.PrefixLen < 0 || a.PrefixLen > ip.BitLen() {
			return false, fmt.Errorf("invalid kernel interface address")
		}
		family := "inet6"
		if ip.Is4() {
			family = "inet"
		}
		if a.Scope == "global" && a.Family == family && !a.Tentative && !a.DADFailed {
			found[netip.PrefixFrom(ip, a.PrefixLen).String()] = true
		}
	}
	for _, address := range addresses {
		if !found[address] {
			return false, nil
		}
	}
	return true, ctx.Err()
}
