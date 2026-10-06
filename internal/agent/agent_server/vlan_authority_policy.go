// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import "fmt"

func configureVLANAuthorityJournal(backend any, dir string, allow, readOnly bool) error {
	if dir == "" {
		if allow && !readOnly {
			return fmt.Errorf("--vlan-authority-journal-dir is required when authoritative VLANs are enabled")
		}
		return nil
	}
	// The backend validates the private root-owned persistent directory. Configure
	// it at startup only; snapshot RPCs must never initialize journal state.
	journal, ok := backend.(interface{ ConfigureVLANAuthorityJournal(string) error })
	if !ok {
		return fmt.Errorf("backend does not support VLAN authority journals")
	}
	if err := journal.ConfigureVLANAuthorityJournal(dir); err != nil {
		return fmt.Errorf("configure VLAN authority journal: %w", err)
	}
	return nil
}
