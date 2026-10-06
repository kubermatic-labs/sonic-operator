// SPDX-License-Identifier: Apache-2.0
// The host recovery binary is independently installed from the agent. Its local
// systemd timer remains operational when the agent or cluster connection stops.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/sonic"
)

func main() {
	boot := flag.Bool("apply-boot-mac", false, "Apply only the typed persisted management MAC at local interface startup")
	flag.Parse()
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
	m, err := sonic.NewSonicRedisAgent(cfg.RedisAddress)
	if err != nil {
		log.Fatal("host recovery backend unavailable")
	}
	e, err := host.NewRecoveryEngine(cfg, m)
	if err != nil {
		log.Fatal("host recovery journal unavailable")
	}
	if e.RecoverExpired(ctx) != nil {
		log.Fatal("host management recovery remains pending")
	}
}
