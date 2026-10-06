// SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	"github.com/ironcore-dev/sonic-operator/internal/releasebundle"
)

func run() error {
	repo := flag.String("repo", ".", "Source repository with ancestry objects")
	release := flag.String("release", "", "Content-addressed release JSON")
	profile := flag.String("profile", "", "Measured base profile JSON")
	baseline := flag.String("baseline", "", "Explicit immutable baseline name")
	input := flag.String("switch-input", "", "Optional explicit public per-switch agent/hook metadata JSON")
	agent := flag.String("agent", "", "Release agent binary")
	supervisor := flag.String("supervisor", "", "Release supervisor binary")
	watchdog := flag.String("watchdog", "", "Release host recovery binary")
	additional := flag.Int64("additional-public-bytes", 0, "Actual other platform/public bundle byte total; TLS reserves full bounded maximum")
	out := flag.String("out", "config/agent/profiles", "Content-addressed source manifest output")
	objectsDir := flag.String("objects-out", "bin/host-artifact-sources", "Immutable ConfigMap JSON output (large; keep out of Git)")
	flag.Parse()
	raw, err := releasebundle.ReadBounded(*release, artifact.MaxMetadataBytes)
	if err != nil {
		return err
	}
	p, err := releasebundle.ReadBounded(*profile, 256<<10)
	if err != nil {
		return err
	}
	var si *releasebundle.SwitchInput
	if *input != "" {
		b, err := releasebundle.ReadBounded(*input, 64<<10)
		if err != nil {
			return err
		}
		si = &releasebundle.SwitchInput{}
		if artifact.Decode(b, si) != nil {
			return fmt.Errorf("invalid public switch metadata")
		}
	}
	s, cms, err := releasebundle.BuildSources(*repo, raw, map[string]string{"agent": *agent, "supervisor": *supervisor, "watchdog": *watchdog}, p, *baseline, si, *additional)
	if err != nil {
		return err
	}
	// All source and aggregate checks precede the first output write.
	for _, cm := range cms {
		b, err := releasebundle.JSON(cm)
		if err != nil {
			return err
		}
		if _, err = releasebundle.WriteAddressed(*objectsDir, b); err != nil {
			return err
		}
	}
	b, err := releasebundle.JSON(s)
	if err != nil {
		return err
	}
	name, err := releasebundle.WriteAddressed(*out, b)
	if err == nil {
		fmt.Println(name)
	}
	return err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
