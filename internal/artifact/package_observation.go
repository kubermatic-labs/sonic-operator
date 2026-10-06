// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"fmt"
	"strings"
)

func validateObservedPackage(observed, before, candidate packageSnapshot) error {
	if observed.Version != 1 {
		return fmt.Errorf("invalid observed package tree")
	}
	allowed := map[string]bool{}
	for name := range before.Entries {
		allowed[name] = true
	}
	for name := range candidate.Entries {
		allowed[name] = true
	}
	// Bounded caches are derived outputs of already-owned source modules, not
	// independent authority to introduce or delete code paths.
	for _, file := range platformModules {
		if !allowed["sonic_platform/"+file] {
			continue
		}
		for _, version := range []string{"311", "313"} {
			for _, opt := range []string{"", ".opt-1", ".opt-2"} {
				allowed["sonic_platform/__pycache__/"+strings.TrimSuffix(file, ".py")+".cpython-"+version+opt+".pyc"] = true
			}
		}
	}
	var total int
	for name, entry := range observed.Entries {
		if !allowed[name] || len(entry.Data) > 1<<20 || entry.Mode&^0777 != 0 {
			return fmt.Errorf("observed package contains an unowned path or mode")
		}
		total += len(entry.Data)
	}
	if total > 32<<20 {
		return fmt.Errorf("observed package exceeds snapshot bound")
	}
	return nil
}
