// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

// netlink's zero-value LinkNotFoundError embeds an unexported nil error. Supply
// a printable wrapper while retaining the real typed error for errors.As.
type lagL3MissingLinkFixture struct{}

func (lagL3MissingLinkFixture) Error() string { return "link not found" }
func (lagL3MissingLinkFixture) Unwrap() error { return netlink.LinkNotFoundError{} }

func TestNetworkLAGL3ExpectedLinkAbsence(t *testing.T) {
	t.Parallel()
	accessErr := errors.New("netlink access denied")
	for _, failure := range []struct {
		name   string
		err    error
		absent bool
	}{
		{"absent", netlink.LinkNotFoundError{}, true},
		{"pointer absent", &netlink.LinkNotFoundError{}, true},
		{"wrapped absent", fmt.Errorf("lookup: %w", lagL3MissingLinkFixture{}), true},
		{"access denied", accessErr, false},
		{"untyped not found", errors.New("link not found"), false},
	} {
		t.Run(failure.name, func(t *testing.T) {
			for _, probe := range []string{"VRF", "L3", "L3 master", "LAG", "LAG member"} {
				t.Run(probe, func(t *testing.T) {
					reads := 0
					link := func(name string) (netlink.Link, error) {
						reads++
						if probe == "L3 master" && name == "Ethernet0" {
							return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{MasterIndex: 10}}, nil
						}
						if probe == "LAG member" && name == "PortChannel10" {
							return &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Index: 10, MTU: 9100}, LinkType: "team"}, nil
						}
						return nil, failure.err
					}
					read := func(context.Context, string) (map[string]string, error) {
						return map[string]string{"NULL": "NULL", "vrf_name": "VrfBlue", "mtu": "9100"}, nil
					}
					run := func(context.Context, ...string) ([]byte, error) {
						t.Fatal("teamd must not be queried when an expected link is absent or unreadable")
						return nil, nil
					}
					var ok bool
					var raw json.RawMessage
					var err error
					switch probe {
					case "VRF":
						ok, raw, err = lagL3VRFRuntime(t.Context(), "VrfBlue", read, link)
					case "L3", "L3 master":
						ok, raw, err = lagL3InterfaceRuntime(t.Context(), "Ethernet0", "VrfBlue", nil, read, link)
					case "LAG", "LAG member":
						ok, raw, err = lagL3PortChannelRuntime(t.Context(), "PortChannel10", []string{"Ethernet0"}, map[string]string{"mtu": "9100", "admin_status": "down"}, read, link, run)
					}
					if ok || reads == 0 {
						t.Fatalf("unexpected runtime result: verified=%t reads=%d", ok, reads)
					}
					if failure.absent {
						if err != nil {
							t.Fatalf("expected observed absence, got error of type %T", err)
						}
						var observed struct {
							KernelLinkExists *bool  `json:"kernelLinkExists"`
							Name             string `json:"name"`
						}
						if json.Unmarshal(raw, &observed) != nil || observed.KernelLinkExists == nil || *observed.KernelLinkExists || observed.Name == "" {
							t.Fatalf("missing absence evidence: %s", raw)
						}
					} else if !errors.Is(err, failure.err) {
						t.Fatalf("access error lost: %v", err)
					}
				})
			}
		})
	}
}

func TestNetworkLAGL3AbsenceDoesNotHideCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	read := func(context.Context, string) (map[string]string, error) { return nil, nil }
	link := func(string) (netlink.Link, error) {
		cancel()
		return nil, netlink.LinkNotFoundError{}
	}
	ok, _, err := lagL3VRFRuntime(ctx, "VrfNew", read, link)
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation hidden by absent link: %t %v", ok, err)
	}
}
