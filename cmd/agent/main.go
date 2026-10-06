// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	server "github.com/ironcore-dev/sonic-operator/internal/agent/agent_server"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
)

func main() {
	if releaseinfo.PrintRequested() {
		return
	}
	server.StartServer()
}
