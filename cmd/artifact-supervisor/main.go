// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/agent/sonic"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func main() {
	if releaseinfo.PrintRequested() {
		return
	}
	if os.Geteuid() != 0 {
		log.Fatal("artifact supervisor requires root")
	}
	const policyPath = "/etc/sonic-operator-agent/artifact-baseline.json"
	info, err := os.Lstat(policyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		log.Fatal("private baseline policy required")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		log.Fatal("baseline policy must be root owned")
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		log.Fatal("baseline policy unavailable")
	}
	var policy artifact.Policy
	if artifact.Decode(data, &policy) != nil {
		log.Fatal("invalid baseline policy")
	}
	fence, err := sonic.NewArtifactWriterFence()
	if err != nil {
		log.Fatal("cooperating writer journals cannot be verified")
	}
	engine, native, err := artifact.NewNativeEngine("/", "/host/sonic-operator-artifacts", policy, fence)
	if err != nil {
		log.Fatal("cannot open exclusive artifact recovery state")
	}
	defer engine.Close()
	if native.BootID() == "" || native.Baseline() != nil {
		log.Fatal("installed boot/image identity unavailable or changed")
	}
	if err := engine.RestoreBoot(); err != nil {
		log.Print("confirmed artifact boot restoration waits for cooperating recovery")
	}
	if err := engine.Tick(time.Now()); err != nil {
		log.Print("artifact boot recovery requires attention")
	}
	socketDir := filepath.Dir(artifact.SocketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		log.Fatal("cannot create private supervisor socket directory")
	}
	if info, err := os.Lstat(socketDir); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		log.Fatal("unsafe supervisor socket directory")
	}
	if err := os.Remove(artifact.SocketPath); err != nil && !os.IsNotExist(err) {
		log.Fatal("cannot replace supervisor socket")
	}
	listener, err := net.Listen("unix", artifact.SocketPath)
	if err != nil {
		log.Fatal("cannot listen on supervisor socket")
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(artifact.SocketPath, 0600); err != nil {
		log.Fatal("cannot protect supervisor socket")
	}
	server := &http.Server{Handler: engine, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: 90 * time.Second, MaxHeaderBytes: 4096}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Print("artifact supervisor listener stopped")
			cancel()
		}
	}()
	if err := notifyReady(); err != nil {
		log.Fatal("cannot confirm boot restoration ordering to systemd")
	}
	engine.PauseRuntime = false
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
			return
		case <-ticker.C:
			if native.Baseline() != nil {
				log.Print("artifact image baseline changed; recovery blocked")
				continue
			}
			if err := engine.RestoreBoot(); err != nil {
				log.Print("artifact boot restoration pending")
			}
			if err := engine.Tick(time.Now()); err != nil {
				log.Print("artifact recovery pending; health or persistence check failed")
			}
		}
	}
}

func notifyReady() error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return os.ErrInvalid
	}
	if address[0] == '@' {
		address = "\x00" + address[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte("READY=1"))
	return err
}
