//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Optional disposable native Redis for developer hosts without Docker. This is
// still a real Redis server, never an existing host database or Lua emulator.
func newLocalNetworkRedis(t *testing.T, server string) *redis.Client {
	t.Helper()
	if !filepath.IsAbs(server) {
		t.Fatal("SONIC_TEST_REDIS_SERVER must be an absolute executable path")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	rdb, stop, err := startLocalNetworkRedis(ctx, server, port, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return rdb
}

func startLocalNetworkRedis(ctx context.Context, server string, port int, dir string) (*redis.Client, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// A password alone does not fence reconnects: Redis's default nopass user
	// accepts HELLO AUTH with any password. A unique ACL user also fences new
	// connections (including clients made from copied options) after port reuse.
	username, password := rand.Text(), rand.Text()
	privateDir, err := os.MkdirTemp(dir, "redis-")
	if err != nil {
		return nil, nil, err
	}
	aclPath := filepath.Join(privateDir, "users.acl")
	acl := "user default off\nuser " + username + " on >" + password + " ~* &* +@all\n"
	if err := os.WriteFile(aclPath, []byte(acl), 0o600); err != nil {
		_ = os.RemoveAll(privateDir)
		return nil, nil, err
	}
	log, err := os.OpenFile(filepath.Join(privateDir, "redis.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.RemoveAll(privateDir)
		return nil, nil, err
	}
	cleanup := func() { _ = log.Close(); _ = os.RemoveAll(privateDir) }
	// Credentials stay in the private ACL file, never argv or startup errors.
	cmd := exec.Command(server, "--bind", "127.0.0.1", "--port", strconv.Itoa(port), "--save", "", "--appendonly", "no", "--dir", privateDir, "--aclfile", aclPath)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, nil, err
	}
	done := make(chan struct{})
	rdb := redis.NewClient(&redis.Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Username: username, Password: password, DB: 4, MaxRetries: -1, ContextTimeoutEnabled: true})
	go func() {
		_ = cmd.Wait()
		_ = rdb.Close()
		cleanup()
		close(done)
	}()
	var once sync.Once
	stop := func() { once.Do(func() { _ = rdb.Close(); _ = cmd.Process.Kill(); <-done }) }
	for {
		if rdb.Ping(ctx).Err() == nil {
			info, err := rdb.Info(ctx, "server").Result()
			if err == nil && strings.Contains(info, "\r\nprocess_id:"+strconv.Itoa(cmd.Process.Pid)+"\r\n") {
				select {
				case <-done:
					stop()
					return nil, nil, fmt.Errorf("disposable Redis exited during startup")
				default:
					return rdb, stop, nil
				}
			}
			stop()
			return nil, nil, fmt.Errorf("disposable Redis process identity mismatch")
		}
		select {
		case <-done:
			stop()
			return nil, nil, fmt.Errorf("disposable Redis failed to start")
		case <-ctx.Done():
			stop()
			return nil, nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
