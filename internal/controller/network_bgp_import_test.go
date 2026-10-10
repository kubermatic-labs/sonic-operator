// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"encoding/json"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBGPPeerImportPrefixesWireShape(t *testing.T) {
	peer := func(prefixes ...api.NetworkPrefix) *api.SwitchBGPPeer {
		return &api.SwitchBGPPeer{ObjectMeta: metav1.ObjectMeta{Name: "p", UID: "uid"}, Spec: api.SwitchBGPPeerSpec{
			NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "leaf"}, ManagementPolicy: api.NetworkManagementPolicyManage},
			Address:             "10.2.1.6", LocalAddress: "10.2.1.7", RemoteASN: 65000, AddressFamilies: []string{"ipv4Unicast"}, AdminState: api.AdminStateDown,
			ImportPrefixes: prefixes,
		}}
	}
	// Unset: the field must not be sent, older agents reject unknown fields.
	r, _, err := networkDesired("BGPPeer", peer())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Spec), "importPrefixes") {
		t.Fatalf("unset importPrefixes sent: %s", r.Spec)
	}
	r, _, err = networkDesired("BGPPeer", peer("10.20.4.0/24", "10.1.0.24/32"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		ImportPrefixes []string `json:"importPrefixes"`
	}
	if err := json.Unmarshal(r.Spec, &spec); err != nil || len(spec.ImportPrefixes) != 2 {
		t.Fatalf("importPrefixes not sent: %s %v", r.Spec, err)
	}
	for _, bad := range [][]api.NetworkPrefix{{"10.20.4.1/24"}, {"10.20.4.0/24", "10.20.4.0/24"}, {"not-a-prefix"}} {
		if _, _, err := networkDesired("BGPPeer", peer(bad...)); err == nil {
			t.Fatalf("accepted invalid importPrefixes %v", bad)
		}
	}
}
