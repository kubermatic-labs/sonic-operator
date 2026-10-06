// SPDX-License-Identifier: Apache-2.0
// host-artifact-release validates real production builds; it never publishes.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/releasebundle"
)

func main() {
	repo := flag.String("repo", ".", "Clean reviewed-source checkout")
	out := flag.String("out", "config/agent/releases", "Content-addressed output directory")
	agent := flag.String("agent", "", "Built Linux amd64 agent")
	supervisor := flag.String("supervisor", "", "Built Linux amd64 supervisor")
	watchdog := flag.String("watchdog", "", "Built Linux amd64 host recovery")
	controller := flag.String("controller", "", "Built Linux amd64 controller")
	fallbacks := flag.String("fallbacks", "", "Comma-separated preapproved fallback agent paths (explicit; seed may equal candidate)")
	flag.Parse()
	r, err := releasebundle.NewRelease(*repo, map[string]string{"agent": *agent, "supervisor": *supervisor, "watchdog": *watchdog, "controller": *controller}, strings.Split(*fallbacks, ","))
	if err == nil {
		var raw []byte
		raw, err = releasebundle.JSON(r)
		if err == nil {
			var name string
			name, err = releasebundle.WriteAddressed(*out, raw)
			if err == nil {
				fmt.Println(name)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
