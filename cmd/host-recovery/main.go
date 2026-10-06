// SPDX-License-Identifier: Apache-2.0
// The host recovery binary is independently installed from the agent. Its local
// systemd timer remains operational when the agent or cluster connection stops.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/agent/sonic"
)

func main() {
	if releaseinfo.PrintRequested() {
		return
	}
	boot := flag.Bool("apply-boot-mac", false, "Apply only the typed persisted management MAC at local interface startup")
	check := flag.Bool("check-installation", false, "Read-only local immutable installation qualification")
	imported := flag.String("apply-imported-boot-mac", "", "Apply a qualified fixed imported boot adapter")
	flag.Parse()
	if flag.NArg() != 0 || (*check && (*boot || *imported != "")) || (*boot && *imported != "") {
		log.Fatal("invalid local recovery mode")
	}
	if os.Geteuid() != 0 {
		log.Fatal("host recovery requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if *boot {
		if (&host.Native{}).ApplyBootMAC(ctx) != nil {
			log.Fatal("management boot MAC could not be verified")
		}
		return
	}
	cfg, err := host.ReadRecoveryConfig()
	if err != nil {
		log.Fatal("host recovery configuration unavailable")
	}
	if *check {
		if _, err := (&host.Native{}).InstallationReceipt(false); err != nil {
			log.Fatal("host installation storage unavailable")
		}
	}
	m, err := sonic.NewSonicRedisAgent(cfg.RedisAddress)
	if err != nil {
		log.Fatal("host recovery backend unavailable")
	}
	n, err := host.NewRecoveryNative(cfg, m)
	if err != nil {
		log.Fatal("host recovery journal unavailable")
	}
	if *check {
		if cfg != host.FleetRecoveryConfig() {
			log.Fatal("unqualified recovery layout")
		}
		p, err := n.QualifyInstalledProfile(ctx)
		if err != nil || n.VerifyRecoveryUnits(ctx) != nil || n.QualifyImportedAdoption(ctx, p) != nil {
			log.Fatal("host installation qualification failed")
		}
		r, err := n.InstallationReceipt(false)
		if err != nil {
			log.Fatal("host installation identity unavailable")
		}
		_ = json.NewEncoder(os.Stdout).Encode(host.PublicInstallationCheck(r))
		return
	}
	if *imported != "" {
		if n.ApplyImportedBootMAC(ctx, *imported) != nil {
			log.Fatal("imported boot MAC could not be verified")
		}
		return
	}
	e, err := host.NewEngine(cfg.JournalDir, n)
	if err != nil {
		log.Fatal("host recovery journal unavailable")
	}
	if e.RecoverExpired(ctx) != nil {
		log.Fatal("host management recovery remains pending")
	}
}
