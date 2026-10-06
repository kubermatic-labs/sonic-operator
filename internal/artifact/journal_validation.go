// SPDX-License-Identifier: Apache-2.0
package artifact

import "fmt"

func validatePackageRecords(records []packageRecovery) error {
	if len(records) != 0 && len(records) != 2 {
		return fmt.Errorf("incomplete package recovery authority")
	}
	seen := map[string]bool{}
	for _, record := range records {
		if record.Observed != "" && !shaPattern.MatchString(record.Observed) {
			return fmt.Errorf("invalid package observation reference")
		}
		if (record.Target != "host" && record.Target != "pmon") || seen[record.Target] || !shaPattern.MatchString(record.Before) || !shaPattern.MatchString(record.Candidate) {
			return fmt.Errorf("invalid package recovery authority")
		}
		seen[record.Target] = true
	}
	return nil
}

func validPhase(phase string) bool {
	switch phase {
	case "Staged", "Installing", "Activating", "AwaitingConfirmation", "Retiring", "RollingBack", "RestoringAgent", "WaitingForeign", "Confirmed", "RolledBack", "Conflict", "RestoringBoot", "ActivatingBoot", "RecoveringBoot":
		return true
	}
	return false
}
func validReason(reason string) bool {
	switch reason {
	case "", "ForeignRecoveryDependency", "WaitingConsumers", "ConsumerMismatch", "PackageRepair", "SourceConflict", "CandidateInstall", "CandidateActivation", "HealthUnverified", "StorageReserve", "BootRecovery":
		return true
	}
	return false
}
