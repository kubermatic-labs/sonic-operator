// SPDX-License-Identifier: Apache-2.0

package sonic

import "errors"

// Reasons are code-owned constants only. Never construct this type from command
// output, config values, filesystem errors or an arbitrary error's text.
type frrMigrationDiagnostic string

func (d frrMigrationDiagnostic) Error() string { return string(d) }

func frrMigrationReason(err error) string {
	var reason frrMigrationDiagnostic
	if errors.As(err, &reason) {
		return string(reason)
	}
	return "PreflightFailed"
}

func frrMigrationCommandReason(command frrMigrationCommand) frrMigrationDiagnostic {
	switch command {
	case frrMigrationConfig:
		return "RunningConfigReadFailed"
	case frrMigrationDaemons:
		return "SupervisorStatusReadFailed"
	case frrMigrationSummary:
		return "BGPSummaryReadFailed"
	case frrMigrationNeighbors:
		return "BGPNeighborsReadFailed"
	case frrMigrationRoutes4:
		return "FRRIPv4RoutesReadFailed"
	case frrMigrationRoutes6:
		return "FRRIPv6RoutesReadFailed"
	case frrMigrationKernel4:
		return "KernelIPv4RoutesReadFailed"
	case frrMigrationKernel6:
		return "KernelIPv6RoutesReadFailed"
	case frrMigrationService:
		return "ServiceReadFailed"
	case frrMigrationCandidate, frrMigrationSeparatedCandidate:
		return "CandidateRenderFailed"
	case frrMigrationInputs:
		return "TemplateInputsReadFailed"
	case frrMigrationStartup:
		return "StartupFilesReadFailed"
	case frrMigrationContainer:
		return "ContainerReadFailed"
	case frrMigrationRestart:
		return "RestartFailedOrTimedOut"
	default:
		return "UnsupportedProbe"
	}
}
