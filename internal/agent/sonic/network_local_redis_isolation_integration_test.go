//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestLocalNetworkRedisRejectsOccupiedPort(t *testing.T) {
	server := os.Getenv("SONIC_TEST_REDIS_SERVER")
	if server == "" {
		t.Skip("native Redis executable not configured")
	}
	occupant := newLocalNetworkRedis(t, server)
	if err := occupant.Set(t.Context(), "isolation-sentinel", "preserve", 0).Err(); err != nil {
		t.Fatal(err)
	}
	_, text, err := net.SplitHostPort(occupant.Options().Addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, stop, err := startLocalNetworkRedis(ctx, server, port, t.TempDir())
	if stop != nil {
		stop()
	}
	if err == nil || client != nil {
		t.Fatal("bind collision returned a client to the occupant")
	}
	if got := occupant.Get(t.Context(), "isolation-sentinel").Val(); got != "preserve" {
		t.Fatalf("occupant was modified: %q", got)
	}
}

func TestLocalNetworkRedisRejectsReplacementAfterChildExit(t *testing.T) {
	server := os.Getenv("SONIC_TEST_REDIS_SERVER")
	if server == "" {
		t.Skip("native Redis executable not configured")
	}
	owned := newLocalNetworkRedis(t, server)
	options := *owned.Options()
	_, text, err := net.SplitHostPort(options.Addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// Exit the actual child without invoking fixture cleanup: the returned
	// client's lifetime and copied options must both remain fenced afterward.
	shutdownLocalNetworkRedis(t, ctx, owned)
	replacement, stop, err := startLocalNetworkRedis(ctx, server, port, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	// Only mutate this replacement after the fixture verifies its owned PID.
	// Reproduce an ordinary Redis's default on/nopass ACL (HELLO AUTH accepts
	// any password for that user), while retaining our administrative client.
	if err := replacement.Do(ctx, "ACL", "SETUSER", "default", "on", "nopass", "~*", "&*", "+@all").Err(); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Set(ctx, "isolation-sentinel", "preserve", 0).Err(); err != nil {
		t.Fatal(err)
	}
	cloned := redis.NewClient(&options)
	t.Cleanup(func() { _ = cloned.Close() })
	for _, tc := range []struct {
		name   string
		client *redis.Client
	}{
		{name: "returned client", client: owned},
		{name: "copied options", client: cloned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Repeat to cover discarding a dead pooled connection and reconnecting.
			for range 3 {
				if err := tc.client.Get(ctx, "isolation-sentinel").Err(); err == nil {
					t.Error("fixture client read replacement Redis")
				}
				if err := tc.client.FlushDB(ctx).Err(); err == nil {
					t.Error("fixture client mutated replacement Redis")
				}
			}
		})
	}
	if got, err := replacement.Get(ctx, "isolation-sentinel").Result(); err != nil || got != "preserve" {
		t.Fatalf("replacement sentinel not preserved: value=%q err=%v", got, err)
	}
	if err := owned.Ping(ctx).Err(); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("exited child's client was not closed: %v", err)
	}
}

func TestLocalNetworkRedisPrivateACLAndCleanup(t *testing.T) {
	server := os.Getenv("SONIC_TEST_REDIS_SERVER")
	if server == "" {
		t.Skip("native Redis executable not configured")
	}
	one := newLocalNetworkRedis(t, server)
	two := newLocalNetworkRedis(t, server)
	if one.Options().Username == "" || one.Options().Username == "default" || one.Options().Username == two.Options().Username || one.Options().Password == "" || one.Options().Password == two.Options().Password {
		t.Fatal("fixtures need distinct non-default usernames and passwords")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, username := range []string{"", "default", two.Options().Username} {
		options := *one.Options()
		options.Username = username
		client := redis.NewClient(&options)
		err := client.Ping(ctx).Err()
		_ = client.Close()
		if err == nil {
			t.Error("fixture accepted credentials without its unique ACL user")
		}
	}
	options := *one.Options()
	options.Password = two.Options().Password
	wrongPassword := redis.NewClient(&options)
	err := wrongPassword.Ping(ctx).Err()
	_ = wrongPassword.Close()
	if err == nil {
		t.Error("fixture accepted another child's password")
	}
	config, err := one.ConfigGet(ctx, "aclfile").Result()
	if err != nil || config["aclfile"] == "" {
		t.Fatal("fixture has no private ACL file")
	}
	aclPath := config["aclfile"]
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{path: filepath.Dir(aclPath), mode: 0o700},
		{path: aclPath, mode: 0o600},
		{path: filepath.Join(filepath.Dir(aclPath), "redis.log"), mode: 0o600},
	} {
		info, err := os.Stat(tc.path)
		if err != nil || info.Mode().Perm() != tc.mode {
			t.Fatalf("fixture resource is missing or has unsafe permissions: %s", tc.path)
		}
	}
	log, err := os.ReadFile(filepath.Join(filepath.Dir(aclPath), "redis.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), one.Options().Username) || strings.Contains(string(log), one.Options().Password) {
		t.Error("fixture log contains credentials")
	}
	shutdownLocalNetworkRedis(t, ctx, one)
	for {
		_, err := os.Stat(filepath.Dir(aclPath))
		if errors.Is(err, os.ErrNotExist) && errors.Is(one.Ping(ctx).Err(), redis.ErrClosed) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("child exit did not close its client and remove private resources")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func shutdownLocalNetworkRedis(t *testing.T, ctx context.Context, owned *redis.Client) {
	t.Helper()
	// Use a separate connection so the fixture's exit watcher can immediately
	// close its returned client without racing this command's response handling.
	options := *owned.Options()
	// Options() has normalized -1 to 0; preserve disabled retries so SHUTDOWN's
	// expected EOF does not trigger attempts to reconnect to the exited server.
	options.MaxRetries = -1
	control := redis.NewClient(&options)
	defer func() { _ = control.Close() }()
	if err := control.ShutdownNoSave(ctx).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalNetworkRedisStartupFailureCleanup(t *testing.T) {
	server := os.Getenv("SONIC_TEST_REDIS_SERVER")
	if server == "" {
		t.Skip("native Redis executable not configured")
	}
	for _, tc := range []struct {
		name   string
		server string
	}{
		{name: "executable missing", server: filepath.Join(t.TempDir(), "missing")},
		{name: "child exits", server: server},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			client, stop, err := startLocalNetworkRedis(ctx, tc.server, -1, dir)
			if stop != nil {
				stop()
			}
			if err == nil || client != nil {
				t.Fatal("startup failure returned a client")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("startup failure left fixture resources behind")
			}
		})
	}
}

func TestLocalNetworkRedisStartupTimeoutCleanup(t *testing.T) {
	// An owned, non-responding listener and a sleeping child exercise a stalled
	// handshake without dialing any host service or leaving a descendant process.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := filepath.Join(t.TempDir(), "stall-redis")
	if err := os.WriteFile(server, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	client, stop, err := startLocalNetworkRedis(ctx, server, listener.Addr().(*net.TCPAddr).Port, dir)
	if stop != nil {
		stop()
	}
	if !errors.Is(err, context.DeadlineExceeded) || client != nil {
		t.Fatalf("stalled startup did not fail on deadline: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("startup deadline did not bound cleanup")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("startup timeout left fixture resources behind")
	}
}

func TestLocalNetworkRedisRejectsDefaultNoPassOccupiedPort(t *testing.T) {
	server := os.Getenv("SONIC_TEST_REDIS_SERVER")
	if server == "" {
		t.Skip("native Redis executable not configured")
	}
	occupant := newLocalNetworkRedis(t, server)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := occupant.Do(ctx, "ACL", "SETUSER", "default", "on", "nopass", "~*", "&*", "+@all").Err(); err != nil {
		t.Fatal(err)
	}
	if err := occupant.Set(ctx, "isolation-sentinel", "preserve", 0).Err(); err != nil {
		t.Fatal(err)
	}
	_, text, err := net.SplitHostPort(occupant.Options().Addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		t.Fatal(err)
	}
	client, stop, err := startLocalNetworkRedis(ctx, server, port, t.TempDir())
	if stop != nil {
		stop()
	}
	if err == nil || client != nil {
		t.Fatal("default/nopass bind collision returned a client to the occupant")
	}
	if got, err := occupant.Get(ctx, "isolation-sentinel").Result(); err != nil || got != "preserve" {
		t.Fatalf("occupant sentinel not preserved: value=%q err=%v", got, err)
	}
}
