// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

type artifactRecoveryKey struct{}

func (m *SonicAgent) artifactAdmission(ctx context.Context) error {
	if recovery, _ := ctx.Value(artifactRecoveryKey{}).(bool); recovery {
		return artifactstate.CheckRecovery(m.artifactStateDir)
	}
	return artifactstate.CheckPending(m.artifactStateDir)
}
func (j *vlanAuthorityJournal) artifactPublication(existingPending bool) error {
	if existingPending {
		return artifactstate.CheckRecovery(j.artifactDir)
	}
	return artifactstate.CheckPending(j.artifactDir)
}
