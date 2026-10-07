// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"fmt"
	"path"

	"golang.org/x/sys/unix"
)

// Covers package before/candidate metadata, atomic rollback replacements and
// journal durability independently of the uploaded/staged payload allocation.
const RecoveryReserveBytes uint64 = 512 << 20

type stagedPlan struct {
	file     File
	record   savedFile
	previous []byte
}

func (e *Engine) available(dir string) (uint64, error) {
	if e.AvailableSpace != nil {
		return e.AvailableSpace(dir)
	}
	for {
		f, err := e.root.Open(dir)
		if err == nil {
			defer func() { _ = f.Close() }()
			var stat unix.Statfs_t
			if err := unix.Fstatfs(int(f.Fd()), &stat); err != nil {
				return 0, err
			}
			return stat.Bavail * uint64(stat.Bsize), nil
		}
		if dir == "." {
			return 0, err
		}
		dir = path.Dir(dir)
	}
}
func (e *Engine) stagingSpace(plans []stagedPlan) error {
	var payload uint64
	for _, p := range plans {
		payload += uint64(len(p.file.Data) + len(p.previous))
		largest := len(p.file.Data)
		if len(p.previous) > largest {
			largest = len(p.previous)
		}
		free, err := e.available(path.Dir(p.record.Path))
		if err != nil || free < uint64(largest)+RecoveryReserveBytes {
			return fmt.Errorf("destination recovery space unavailable")
		}
	}
	free, err := e.available(e.state)
	if err != nil || free < payload+RecoveryReserveBytes {
		return fmt.Errorf("staging would consume recovery reserve")
	}
	return nil
}
func (e *Engine) pruneAbandoned() error {
	// A visible rename is not sufficient: establish directory durability before
	// deciding which payloads are unreferenced, including after save errors.
	if err := e.syncDir(e.state); err != nil {
		return err
	}
	j, err := e.load()
	if err != nil {
		return err
	}
	if j == nil {
		j = &journal{}
	}
	return e.pruneContent(j)
}
