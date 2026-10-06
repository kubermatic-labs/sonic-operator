// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

func (n *Native) inputCommand(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if n.RunInput != nil {
		return n.RunInput(ctx, input, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bounded native input operation failed")
	}
	if len(out) > 48<<20 {
		return nil, fmt.Errorf("native input response too large")
	}
	return out, nil
}
