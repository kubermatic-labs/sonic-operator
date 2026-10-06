// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestContentPublicationCrashWorker(t *testing.T) {
	root := os.Getenv("ARTIFACT_CONTENT_CRASH_ROOT")
	if root == "" {
		t.Skip("subprocess only")
	}
	data := []byte(`{"ports":[]}`)
	_, err := uploadContent(context.Background(), root, os.Getenv("ARTIFACT_CONTENT_CRASH_SESSION"), Digest(data), 0, data, func(phase string) {
		if phase == os.Getenv("ARTIFACT_CONTENT_CRASH_PHASE") {
			os.Exit(79)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("publication boundary was not reached")
}

func TestCompletedPartialRecoversPublicationAndLostAcknowledgement(t *testing.T) {
	for _, phase := range []string{"partial-synced", "blob-published"} {
		t.Run(phase, func(t *testing.T) {
			e, root := testEngine(t)
			b := testBundle()
			data := b.Files[0].Data
			b.Files[0].Data = nil
			session, _, err := PrepareContent(context.Background(), root, b, "stage", []Blob{{SHA256: Digest(data), Size: uint64(len(data))}})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestContentPublicationCrashWorker$")
			cmd.Env = append(os.Environ(), "ARTIFACT_CONTENT_CRASH_ROOT="+root, "ARTIFACT_CONTENT_CRASH_SESSION="+session.ID, "ARTIFACT_CONTENT_CRASH_PHASE="+phase)
			err = cmd.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 79 {
				t.Fatalf("no publication crash: %v", err)
			}
			resumed, offsets, err := PrepareContent(context.Background(), root, b, "stage", session.Blobs)
			if err != nil || len(offsets) != 1 || offsets[0].Offset != uint64(len(data)) {
				t.Fatalf("resume: %+v %v", offsets, err)
			}
			ready, err := HydrateContent(context.Background(), root, b, "stage", resumed.ID)
			if err != nil || !bytes.Equal(ready.Files[0].Data, data) {
				t.Fatalf("full offset did not name a verified blob: %v", err)
			}
			result, err := e.Execute(context.Background(), Request{Operation: "stage", Bundle: b, ContentSession: resumed.ID})
			if err != nil || result.Phase != "Staged" {
				t.Fatalf("resumed dispatch: %+v %v", result, err)
			}
			if err := e.Tick(time.Now()); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(filepath.Join(root, "usr/share/sonic/device/test/platform.json"))
			if !bytes.Equal(got, data) {
				t.Fatal("resumed content was not installed")
			}
			if _, err := os.Stat(filepath.Join(root, ContentDir, "partial", Digest(data))); !os.IsNotExist(err) {
				t.Fatal("published partial retained")
			}
		})
	}
}

func TestInvalidFullPartialIsResetWithoutAcknowledgingCompletion(t *testing.T) {
	_, root := testEngine(t)
	b := testBundle()
	data := b.Files[0].Data
	b.Files[0].Data = nil
	session, _, err := PrepareContent(context.Background(), root, b, "stage", []Blob{{SHA256: Digest(data), Size: uint64(len(data))}})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, ContentDir, "partial", Digest(data))
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	next, offsets, err := PrepareContent(context.Background(), root, b, "stage", session.Blobs)
	if err != nil || offsets[0].Offset != 0 {
		t.Fatalf("unverified partial acknowledged: %+v %v", offsets, err)
	}
	if _, err := UploadContent(context.Background(), root, next.ID, Digest(data), 0, data); err != nil {
		t.Fatal(err)
	}
	if _, err := HydrateContent(context.Background(), root, b, "stage", next.ID); err != nil {
		t.Fatal(err)
	}
}
