// SPDX-License-Identifier: Apache-2.0

//go:build legacy_release

package releaseinfo

// compiledDeclaration declares only the eight legacy capabilities. Use it for
// builds that must be accepted next to, and roll back to, agents that predate
// the imported MAC unit reader. The code still contains that reader; only the
// declared release compatibility differs.
var compiledDeclaration = LegacyMarker
