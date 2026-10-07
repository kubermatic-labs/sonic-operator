// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedChunksReuseContentAndRejectReadPayloads(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte("c"), 2*ChunkBytes+11)
	b := testBundle()
	b.Files = []File{{Slot: "AgentBinary", SHA256: Digest(data)}}
	session, offsets, err := PrepareContent(context.Background(), root, b, "stage", []Blob{{SHA256: Digest(data), Size: uint64(len(data))}})
	if err != nil {
		t.Fatal(err)
	}
	if offsets[0].Offset != 0 {
		t.Fatal("unexpected cached content")
	}
	for offset := 0; offset < len(data); {
		end := offset + ChunkBytes
		if end > len(data) {
			end = len(data)
		}
		next, err := UploadContent(context.Background(), root, session.ID, Digest(data), uint64(offset), data[offset:end])
		if err != nil || next != uint64(end) {
			t.Fatalf("chunk %v", err)
		}
		offset = end
	}
	hydrated, err := HydrateContent(context.Background(), root, b, "stage", session.ID)
	if err != nil || !bytes.Equal(hydrated.Files[0].Data, data) {
		t.Fatal("content not reassembled")
	}
	_, offsets, err = PrepareContent(context.Background(), root, b, "stage", session.Blobs)
	if err != nil || offsets[0].Offset != uint64(len(data)) {
		t.Fatal("steady-state content was not reused")
	}
	b.Bootstrap = &Bootstrap{Supervisor: []byte("unnecessary read payload")}
	if MetadataOnly(b) == nil {
		t.Fatal("read envelope accepted bootstrap payload")
	}
}

func TestCanceledEngineQueueNeverRunsNativeWork(t *testing.T) {
	e, _ := testEngine(t)
	called := false
	e.Health = func() error { called = true; return nil }
	b := testBundle()
	e.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.ObserveContext(ctx, b); done <- err }()
	if err := <-done; err == nil {
		t.Fatal("canceled queued request succeeded")
	}
	e.mu.Unlock()
	if called {
		t.Fatal("canceled queued work reached native health")
	}
}

func TestMaximumBinaryChunkTransferHasFixedWorkingMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum transfer characterization")
	}
	root := t.TempDir()
	chunk := bytes.Repeat([]byte("x"), ChunkBytes)
	const count = 96 << 20 / ChunkBytes
	hash := sha256.New()
	for range count {
		hash.Write(chunk)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	b := testBundle()
	b.Files = []File{{Slot: "AgentBinary", SHA256: digest}}
	session, _, err := PrepareContent(context.Background(), root, b, "stage", []Blob{{SHA256: digest, Size: 96 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var initial, peak, current runtime.MemStats
	runtime.ReadMemStats(&initial)
	for i := 0; i < count; i++ {
		if _, err := UploadContent(context.Background(), root, session.ID, digest, uint64(i*ChunkBytes), chunk); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&current)
		if current.HeapAlloc > peak.HeapAlloc {
			peak = current
		}
	}
	growth := uint64(0)
	if peak.HeapAlloc > initial.HeapAlloc {
		growth = peak.HeapAlloc - initial.HeapAlloc
	}
	t.Logf("96-MiB transfer peak additional Go heap: %d bytes", growth)
	if growth > 32<<20 {
		t.Fatal("chunk transfer memory scaled with binary size")
	}
	if _, err := os.Stat(root + ContentDir + "/blobs/" + digest); err != nil {
		t.Fatal(err)
	}
}

func TestMaximumAdmittedStageMemoryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum stage characterization")
	}
	seed, _ := bootstrapFixture(t)
	header := seed.Bootstrap.Supervisor
	e, root := testEngine(t)
	p := filepath.Join(root, "usr/local/sbin/sonic-operator-agent")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(header)
	_ = f.Truncate(96 << 20)
	_ = f.Close()
	runtime.GC()
	var initial runtime.MemStats
	runtime.ReadMemStats(&initial)
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			for old := peak.Load(); m.HeapAlloc > old && !peak.CompareAndSwap(old, m.HeapAlloc); old = peak.Load() {
			}
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	data := make([]byte, 96<<20)
	copy(data, header)
	b := testBundle()
	b.Files = []File{{Slot: "AgentBinary", Data: data, SHA256: Digest(data)}}
	completeAgentFixture(t, e, &b)
	_, err = e.Ensure(b, time.Now())
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	growth := peak.Load() - initial.HeapAlloc
	t.Logf("maximum admitted 96-MiB binary stage peak additional Go heap: %d bytes", growth)
	if growth > 512<<20 {
		t.Fatal("stage exceeded declared Go heap budget")
	}
}
