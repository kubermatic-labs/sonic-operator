// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"fmt"
	"strings"
)

func verifyAgentTLSArguments(raw []byte) error {
	args := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
	expected := map[string]string{"--tls-cert-file": "/etc/sonic-operator-agent/tls.crt", "--tls-key-file": "/etc/sonic-operator-agent/tls.key", "--tls-client-ca-file": "/etc/sonic-operator-agent/ca.crt"}
	seen := map[string]bool{}
	for i, arg := range args {
		flag, value, hasValue := strings.Cut(string(arg), "=")
		want, ok := expected[flag]
		if !ok {
			continue
		}
		if !hasValue && i+1 < len(args) {
			value = string(args[i+1])
		}
		if seen[flag] || value != want {
			return fmt.Errorf("agent TLS does not consume the declared file paths")
		}
		seen[flag] = true
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("agent TLS file consumption is not explicit")
	}
	return nil
}
