// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
)

func main() {
	caps, err := releaseinfo.BinaryCapabilities([]byte("probe"))
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"current": releaseinfo.Current().Capabilities, "probe": caps, "err": err != nil})
}
