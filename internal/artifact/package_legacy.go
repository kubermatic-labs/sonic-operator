// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"errors"
	"fmt"
	"io/fs"
)

// Legacy preparation published both fixed payload pairs before native mutation.
// Retain that pair's Before-as-observation contract when resuming partial apply.
// The first inheritance-capable reader omitted false PackagesPrepared too, but
// wrote only digest-addressed payloads; those journals must still be prepared.
func (e *Engine) normalizeLegacyPackages(j *journal) error {
	if len(j.Packages) == 0 {
		return nil
	}
	for _, entry := range j.Packages {
		if entry.Observed != "" {
			return nil
		}
	}
	found := 0
	for _, entry := range j.Packages {
		for _, which := range []string{"before", "candidate"} {
			raw, _, err := e.read(e.packagePath(j, entry.Target, which))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			hash := entry.Before
			if which == "candidate" {
				hash = entry.Candidate
			}
			var snapshot packageSnapshot
			if Digest(raw) != hash || Decode(raw, &snapshot) != nil || snapshot.Version != 1 || len(snapshot.Entries) == 0 {
				return fmt.Errorf("invalid legacy package authority")
			}
			found++
		}
	}
	if found == 0 {
		// An absent legacy pair is not an inherited pair. Require the newer
		// digest-addressed authority before allowing fresh preparation instead.
		for _, entry := range j.Packages {
			for _, which := range []string{"before", "candidate"} {
				if _, err := e.readPackagePayload(j, entry, which); err != nil {
					return fmt.Errorf("missing package preparation authority: %w", err)
				}
			}
		}
		return nil
	}
	if found != 4 {
		return fmt.Errorf("incomplete legacy package authority")
	}
	j.PackagesPrepared = true
	return nil
}
