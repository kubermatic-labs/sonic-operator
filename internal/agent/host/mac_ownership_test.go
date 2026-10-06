// SPDX-License-Identifier: Apache-2.0
package host

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementPublicationRecordsMACOwnership(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign", true: "owned"}[owned], func(t *testing.T) {
			e, f, _ := newTestEngine(t)
			q := managementRequest()
			if !owned {
				q.Management.MAC = ""
				f.state.MAC = ""
			}
			q.Management.Addresses[0].Prefix = "10.0.0.99/24"
			if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(e.dir, "host.json"))
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Pending struct {
					MACOwned *bool  `json:"macOwned"`
					Observed string `json:"observedActiveMAC"`
				} `json:"pending"`
			}
			if json.Unmarshal(raw, &envelope) != nil || envelope.Pending.MACOwned == nil || *envelope.Pending.MACOwned != owned || envelope.Pending.Observed != f.activeMAC {
				t.Fatalf("ownership/observation not recorded: %s", raw)
			}
		})
	}
}
