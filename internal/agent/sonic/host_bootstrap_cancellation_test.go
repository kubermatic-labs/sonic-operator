// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

type cancellationBootstrapFence struct {
	*ArtifactWriterFence
	qualify func(context.Context) error
}

func (f *cancellationBootstrapFence) QualifyHostBootstrap(ctx context.Context, _ []byte, _ bool) error {
	return f.qualify(ctx)
}

func cancellationBootstrapBundle(t *testing.T) artifact.Bundle {
	t.Helper()
	profile, err := os.ReadFile("../../../config/agent/profiles/202411.1216684-48c2d4c3e.json")
	if err != nil {
		t.Fatal(err)
	}
	elf := make([]byte, 120)
	copy(elf, []byte{'\x7f', 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[16:], 2)
	binary.LittleEndian.PutUint16(elf[18:], 62)
	binary.LittleEndian.PutUint32(elf[20:], 1)
	binary.LittleEndian.PutUint64(elf[32:], 64)
	binary.LittleEndian.PutUint16(elf[52:], 64)
	binary.LittleEndian.PutUint16(elf[54:], 56)
	binary.LittleEndian.PutUint16(elf[56:], 1)
	binary.LittleEndian.PutUint32(elf[64:], 1)
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	return artifact.Bundle{Owner: "owner", Target: "target", Generation: 1, Baseline: "baseline", Files: []artifact.File{{Slot: "PlatformJSON", SHA256: artifact.Digest([]byte("{}"))}}, Agent: &artifact.AgentOptions{HostGuard: true, BindAddress: "0.0.0.0", Port: 50051}, Bootstrap: &artifact.Bootstrap{SupervisorSHA256: artifact.Digest(elf), PolicySHA256: artifact.Digest([]byte("policy")), UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit)), HostRecovery: &artifact.HostRecoveryBootstrap{Binary: elf, BinarySHA256: artifact.Digest(elf), Profile: profile, ProfileSHA256: artifact.Digest(profile), ServiceSHA256: artifact.Digest(host.RecoveryServiceUnit()), TimerSHA256: artifact.Digest(host.RecoveryTimerUnit()), ConfigSHA256: artifact.Digest(cfg), JournalLayout: "FleetHostV1"}}}
}

func stalledQualificationRedis(t *testing.T, stallAt int32) (string, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var pings atomic.Int32
	t.Cleanup(func() { unblock(); _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
					if err != nil {
						return
					}
					args := []string{}
					for i := 0; i < count; i++ {
						line, err = reader.ReadString('\n')
						if err != nil {
							return
						}
						size, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
						if err != nil {
							return
						}
						raw := make([]byte, size+2)
						if _, err = io.ReadFull(reader, raw); err != nil {
							return
						}
						args = append(args, string(raw[:size]))
					}
					if len(args) == 0 {
						return
					}
					reply := "+OK\r\n"
					switch strings.ToLower(args[0]) {
					case "hello":
						reply = "-ERR unknown command 'hello'\r\n"
					case "ping":
						if pings.Add(1) == stallAt {
							close(entered)
							<-release
						}
						reply = "+PONG\r\n"
					case "eval":
						reply = "$2\r\n[]\r\n"
					}
					if _, err = io.WriteString(conn, reply); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), entered, unblock
}

func TestHostBootstrapQualificationCancellationReleasesWriterLocks(t *testing.T) {
	for _, phase := range []string{"initial", "final"} {
		for _, path := range []string{"constructor", "connection", "cached"} {
			t.Run(phase+"/"+path, func(t *testing.T) {
				stallAt := int32(1)
				if path == "connection" {
					stallAt = 2
				}
				if path == "cached" {
					stallAt = 3
				}
				address, entered, unblock := stalledQualificationRedis(t, stallAt)
				root := t.TempDir()
				cfg := host.FleetRecoveryConfig()
				m := &SonicAgent{journalDir: filepath.Join(root, cfg.VLANJournalDir), breakoutJournalDir: filepath.Join(root, cfg.BreakoutJournalDir), networkJournalDir: filepath.Join(root, cfg.NetworkJournalDir)}
				fence := &ArtifactWriterFence{agent: m}
				hostDir := filepath.Join(root, cfg.JournalDir)
				for _, dir := range []string{m.journalDir, m.breakoutJournalDir, m.networkJournalDir, hostDir} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
					if dir != hostDir {
						if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				exclusive := func(ctx context.Context, fn func() error) error {
					return fence.WithMutation(ctx, func() error { return host.WithArtifactExclusion(ctx, hostDir, fn) })
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				calls := 0
				qualified := &cancellationBootstrapFence{ArtifactWriterFence: fence, qualify: func(ctx context.Context) error {
					calls++
					if phase == "final" && calls == 1 {
						return nil
					}
					return withHostBootstrapBackend(ctx, address, func(b *SonicAgent) error {
						if path == "cached" {
							if _, _, err := b.vlanChangeSnapshot(ctx); err != nil {
								return err
							}
						}
						_, _, err := b.vlanChangeSnapshot(ctx)
						return err
					})
				}}
				bundle := cancellationBootstrapBundle(t)
				go func() {
					done <- artifact.EnsureHostBootstrap(ctx, root, bundle, qualified, func(context.Context) error { return nil })
				}()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					unblock()
					t.Fatal("qualification did not enter Redis")
				}
				cancel()
				select {
				case err := <-done:
					if err == nil {
						t.Error("canceled qualification succeeded")
					}
				case <-time.After(250 * time.Millisecond):
					t.Error("canceled Redis qualification retained writer/host locks")
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("fixture failed to release qualification")
					}
				}
				second, stop := context.WithTimeout(t.Context(), time.Second)
				defer stop()
				if err := exclusive(second, func() error { return nil }); err != nil {
					t.Fatal(fmt.Errorf("second writer remained blocked: %w", err))
				}
			})
		}
	}
}
