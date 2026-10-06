// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"errors"
	"fmt"
	"io/fs"
)

func (e *Engine) readPackagePayload(j *journal, record packageRecovery, which string) ([]byte, error) {
	hash := record.Before
	if which == "candidate" {
		hash = record.Candidate
	}
	if which == "observed" {
		hash = record.Observed
	}
	if record.Target != "host" && record.Target != "pmon" || !shaPattern.MatchString(hash) {
		return nil, fmt.Errorf("invalid package payload reference")
	}
	data, _, err := e.read(e.packagePath(j, record.Target, which, hash))
	// Read-only compatibility for the earlier, hash-verified fixed filename.
	if errors.Is(err, fs.ErrNotExist) {
		data, _, err = e.read(e.packagePath(j, record.Target, which))
	}
	if err != nil || Digest(data) != hash {
		return nil, fmt.Errorf("protected package payload unavailable")
	}
	return data, nil
}

// Every generation owns its own durable copy. In particular, changing only an
// agent/certificate cannot discard the last-confirmed package tree when the old
// token is collected. Before and Candidate both name the currently confirmed
// tree until an actual platform mutation publishes a replacement pair.
func (e *Engine) inheritPackages(j *journal) error {
	if j.Active == nil || len(j.Active.Packages) == 0 {
		return nil
	}
	if !shaPattern.MatchString(j.Active.LauncherManifest) {
		return fmt.Errorf("confirmed package lacks launcher authority")
	}
	source := *j
	source.Token = j.Active.Token
	records := make([]packageRecovery, 0, len(j.Active.Packages))
	for _, old := range j.Active.Packages {
		data, err := e.readPackagePayload(&source, old, "candidate")
		if err != nil {
			return err
		}
		record := packageRecovery{Target: old.Target, Before: old.Candidate, Candidate: old.Candidate}
		for _, which := range []string{"before", "candidate"} {
			if err := e.atomic(e.packagePath(j, record.Target, which, old.Candidate), data, 0600); err != nil {
				return err
			}
		}
		records = append(records, record)
	}
	j.Packages = records
	j.LauncherManifest = j.Active.LauncherManifest
	return nil
}
