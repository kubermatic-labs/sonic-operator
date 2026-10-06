// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"encoding/hex"
	"fmt"
	"path"
)

// Only discard content after an atomic journal save identifies the complete
// reference set. On any uncertain save error all recovery payloads are retained.
func (e *Engine) pruneContent(j *journal) error {
	directory, err := e.root.Open(e.state)
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || len(name) != 32 || name == j.Token || (j.Active != nil && name == j.Active.Token) {
			continue
		}
		if _, err := hex.DecodeString(name); err != nil {
			continue
		}
		p := path.Join(e.state, name)
		if err := e.safe(p); err != nil {
			return err
		}
		if err := e.root.RemoveAll(p); err != nil {
			return fmt.Errorf("cannot prune unreferenced artifact content")
		}
	}
	return e.syncDir(e.state)
}
