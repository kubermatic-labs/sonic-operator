// SPDX-License-Identifier: Apache-2.0
package artifactstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReservationGatesPublicationAndOnlyAdmitsRecoveryAfterAgentRestore(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	if err := CheckPending(dir); err != nil {
		t.Fatal(err)
	}
	r := Reservation{Version: 1, Owner: "uid", Token: "0123456789abcdef0123456789abcdef", Manifest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: "Active"}
	if err := Store(dir, r); err != nil {
		t.Fatal(err)
	}
	if CheckPending(dir) == nil {
		t.Fatal("active artifact reservation admitted new work")
	}
	if err := CheckRecovery(dir); err != nil {
		t.Fatal("recorded recovery was deadlocked")
	}
	r.Phase = "ForeignRecovery"
	if err := Store(dir, r); err != nil {
		t.Fatal(err)
	}
	if CheckPending(dir) == nil {
		t.Fatal("new work admitted during dependency recovery")
	}
	if err := CheckRecovery(dir); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "reservation.json"), []byte(`{"version":1,"phase":"unknown"}`), 0600)
	if CheckPending(dir) == nil {
		t.Fatal("corrupt reservation treated as absent")
	}
}
