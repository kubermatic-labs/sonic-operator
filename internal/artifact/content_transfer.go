// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
)

const ContentDir = "/host/sonic-operator-artifact-content"
const ChunkBytes = 256 << 10
const MaxMetadataBytes = 64 << 10
const ContentCacheBytes = 256 << 20

type Blob struct {
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}
type ContentSession struct {
	ID        string `json:"id"`
	Identity  string `json:"identity"`
	Operation string `json:"operation"`
	Blobs     []Blob `json:"blobs"`
}
type ContentOffset struct {
	SHA256 string `json:"sha256"`
	Offset uint64 `json:"offset"`
}

func MetadataOnly(b Bundle) error {
	for _, f := range b.Files {
		if len(f.Data) != 0 {
			return fmt.Errorf("metadata envelope contains file content")
		}
	}
	if b.Bootstrap != nil && (len(b.Bootstrap.Supervisor) != 0 || len(b.Bootstrap.Policy) != 0) {
		return fmt.Errorf("metadata envelope contains bootstrap content")
	}
	if b.Bootstrap != nil {
		if err := b.Bootstrap.HostRecovery.payloads(func(_ string, p *[]byte, _ uint64) error {
			if len(*p) != 0 {
				return fmt.Errorf("metadata envelope contains host content")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return b.Validate(false)
}
func wantedBlobs(b Bundle, op string) map[string]uint64 {
	out := map[string]uint64{}
	if op == "stage" {
		for _, f := range b.Files {
			limit := uint64(1 << 20)
			if f.Slot == "AgentBinary" {
				limit = 96 << 20
			}
			if f.Slot == "PlatformWheel" {
				limit = 16 << 20
			}
			out[f.SHA256] = limit
		}
	}
	if op == "bootstrap" && b.Bootstrap != nil {
		out[b.Bootstrap.SupervisorSHA256] = 96 << 20
		out[b.Bootstrap.PolicySHA256] = 256 << 10
		_ = b.Bootstrap.HostRecovery.payloads(func(hash string, _ *[]byte, limit uint64) error {
			if old, ok := out[hash]; !ok || limit < old {
				out[hash] = limit
			}
			return nil
		})
	}
	return out
}
func openContent(root string) (*Engine, error) {
	return Open(root, ContentDir, Policy{Baseline: "content-cache"}, func() error { return nil }, func() error { return nil })
}
func openContentFile(e *Engine, p string) (*os.File, error) {
	if err := e.safe(p); err != nil {
		return nil, err
	}
	f, err := e.root.Open(p)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, fmt.Errorf("untrusted content cache file")
	}
	return f, nil
}
func contentFileMatches(f *os.File, blob Blob) (bool, error) {
	if _, err := f.Seek(0, 0); err != nil {
		return false, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, int64(blob.Size)+1))
	if err != nil {
		return false, err
	}
	return uint64(n) == blob.Size && hex.EncodeToString(h.Sum(nil)) == blob.SHA256, nil
}
func removeContentFile(e *Engine, p string) error {
	f, err := openContentFile(e, p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f.Close()
	if err := e.root.Remove(p); err != nil {
		return err
	}
	return e.syncDir(path.Dir(p))
}

// A full offset is an assertion of a durable, hash-verified blob, never just a
// partial's length. Called under the content-store lock, including after restart.
func cachedSize(e *Engine, blob Blob) (uint64, error) {
	complete := path.Join(e.state, "blobs", blob.SHA256)
	partial := path.Join(e.state, "partial", blob.SHA256)
	f, err := openContentFile(e, complete)
	if err == nil {
		matches, checkErr := contentFileMatches(f, blob)
		if checkErr == nil && matches {
			checkErr = f.Sync()
		}
		f.Close()
		if checkErr != nil {
			return 0, checkErr
		}
		if matches {
			if err := e.syncDir(path.Dir(complete)); err != nil {
				return 0, err
			}
			if err := removeContentFile(e, partial); err != nil {
				return 0, err
			}
			return blob.Size, nil
		}
		if err := removeContentFile(e, complete); err != nil {
			return 0, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	f, err = openContentFile(e, partial)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return 0, err
	}
	size := uint64(info.Size())
	if size < blob.Size {
		err = f.Sync()
		f.Close()
		return size, err
	}
	matches, checkErr := contentFileMatches(f, blob)
	if checkErr == nil && matches {
		checkErr = f.Sync()
	}
	f.Close()
	if checkErr != nil {
		return 0, checkErr
	}
	if !matches {
		if err := removeContentFile(e, partial); err != nil {
			return 0, err
		}
		return 0, nil
	}
	if err := e.root.Rename(partial, complete); err != nil {
		return 0, err
	}
	if err := e.syncDir(path.Dir(complete)); err != nil {
		return 0, err
	}
	if err := e.syncDir(path.Dir(partial)); err != nil {
		return 0, err
	}
	return blob.Size, nil
}
func PrepareContent(ctx context.Context, root string, b Bundle, op string, blobs []Blob) (ContentSession, []ContentOffset, error) {
	var empty ContentSession
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	if err := MetadataOnly(b); err != nil {
		return empty, nil, err
	}
	wanted := wantedBlobs(b, op)
	if len(wanted) == 0 || len(blobs) != len(wanted) {
		return empty, nil, fmt.Errorf("invalid content manifest")
	}
	seen := map[string]bool{}
	var total uint64
	for _, blob := range blobs {
		limit, ok := wanted[blob.SHA256]
		if !ok || seen[blob.SHA256] || blob.Size == 0 || blob.Size > limit {
			return empty, nil, fmt.Errorf("content outside bounded declaration")
		}
		seen[blob.SHA256] = true
		total += blob.Size
	}
	if total > MaxBundleBytes {
		return empty, nil, fmt.Errorf("content bundle too large")
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].SHA256 < blobs[j].SHA256 })
	e, err := openContent(root)
	if err != nil {
		return empty, nil, err
	}
	defer e.Close()
	if err := e.mkdirDurable(path.Join(e.state, "blobs")); err != nil {
		return empty, nil, err
	}
	if err := e.mkdirDurable(path.Join(e.state, "partial")); err != nil {
		return empty, nil, err
	}
	session := ContentSession{Identity: b.Identity(), Operation: op, Blobs: blobs}
	raw, _, err := e.read(path.Join(e.state, "session.json"))
	if err == nil {
		var old ContentSession
		if Decode(raw, &old) == nil {
			a, _ := json.Marshal(old.Blobs)
			c, _ := json.Marshal(blobs)
			if old.Identity == session.Identity && old.Operation == op && string(a) == string(c) {
				session.ID = old.ID
			}
		}
	}
	if session.ID == "" {
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			return empty, nil, err
		}
		session.ID = hex.EncodeToString(token)
	}
	offsets := make([]ContentOffset, 0, len(blobs))
	var missing uint64
	for _, blob := range blobs {
		offset, err := cachedSize(e, blob)
		if err != nil {
			return empty, nil, err
		}
		offsets = append(offsets, ContentOffset{blob.SHA256, offset})
		missing += blob.Size - offset
	}
	// Cache eviction never touches the supervisor's recovery payloads. Keep the
	// current manifest and evict only unrelated completed/abandoned uploads.
	var used uint64
	type file struct {
		path string
		size uint64
	}
	var evict []file
	for _, folder := range []string{"blobs", "partial"} {
		dir, _ := e.root.Open(path.Join(e.state, folder))
		entries, err := dir.ReadDir(-1)
		dir.Close()
		if err != nil {
			return empty, nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !shaPattern.MatchString(entry.Name()) {
				return empty, nil, fmt.Errorf("unknown cache entry")
			}
			info, err := entry.Info()
			if err != nil {
				return empty, nil, err
			}
			size := uint64(info.Size())
			used += size
			if !seen[entry.Name()] {
				evict = append(evict, file{path.Join(e.state, folder, entry.Name()), size})
			}
		}
	}
	for _, f := range evict {
		if used+missing <= ContentCacheBytes {
			break
		}
		if err := e.root.Remove(f.path); err != nil {
			return empty, nil, err
		}
		used -= f.size
	}
	if used+missing > ContentCacheBytes {
		return empty, nil, fmt.Errorf("content cache full")
	}
	free, err := e.available(e.state)
	if err != nil || free < missing+RecoveryReserveBytes {
		return empty, nil, fmt.Errorf("content transfer lacks recovery reserve")
	}
	raw, _ = json.Marshal(session)
	if err := e.atomic(path.Join(e.state, "session.json"), raw, 0600); err != nil {
		return empty, nil, err
	}
	return session, offsets, nil
}
func UploadContent(ctx context.Context, root, sessionID, digest string, offset uint64, data []byte) (uint64, error) {
	return uploadContent(ctx, root, sessionID, digest, offset, data, nil)
}
func uploadContent(ctx context.Context, root, sessionID, digest string, offset uint64, data []byte, fault func(string)) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(data) == 0 || len(data) > ChunkBytes || !shaPattern.MatchString(digest) {
		return 0, fmt.Errorf("invalid bounded chunk")
	}
	e, err := openContent(root)
	if err != nil {
		return 0, err
	}
	defer e.Close()
	raw, _, err := e.read(path.Join(e.state, "session.json"))
	var session ContentSession
	if err != nil || Decode(raw, &session) != nil || session.ID != sessionID {
		return 0, fmt.Errorf("stale content session")
	}
	var size uint64
	for _, blob := range session.Blobs {
		if blob.SHA256 == digest {
			size = blob.Size
		}
	}
	if size == 0 || offset > size || uint64(len(data)) > size-offset {
		return 0, fmt.Errorf("chunk outside content manifest")
	}
	partial := path.Join(e.state, "partial", digest)
	if err := e.safe(partial); err != nil {
		return 0, err
	}
	f, err := e.root.OpenFile(partial, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || uint64(info.Size()) != offset {
		return 0, fmt.Errorf("chunk offset conflict")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if _, err := f.WriteAt(data, int64(offset)); err != nil {
		return 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	next := offset + uint64(len(data))
	if next == size {
		if fault != nil {
			fault("partial-synced")
		}
		verified, err := cachedSize(e, Blob{SHA256: digest, Size: size})
		if err != nil {
			return 0, err
		}
		if verified != size {
			return 0, fmt.Errorf("completed content hash mismatch")
		}
		if fault != nil {
			fault("blob-published")
		}
	}
	return next, nil
}
func HydrateContent(ctx context.Context, root string, b Bundle, op, sessionID string) (Bundle, error) {
	if err := MetadataOnly(b); err != nil {
		return b, err
	}
	e, err := openContent(root)
	if err != nil {
		return b, err
	}
	defer e.Close()
	raw, _, err := e.read(path.Join(e.state, "session.json"))
	var session ContentSession
	if err != nil || Decode(raw, &session) != nil || session.ID != sessionID || session.Identity != b.Identity() || session.Operation != op {
		return b, fmt.Errorf("content session identity mismatch")
	}
	read := func(hash string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, _, err := e.read(path.Join(e.state, "blobs", hash))
		if err != nil || Digest(data) != hash {
			return nil, fmt.Errorf("verified content unavailable")
		}
		return data, nil
	}
	if op == "stage" {
		b.Files = append([]File(nil), b.Files...)
		for i := range b.Files {
			b.Files[i].Data, err = read(b.Files[i].SHA256)
			if err != nil {
				return b, err
			}
		}
	} else if op == "bootstrap" && b.Bootstrap != nil {
		bootstrap := *b.Bootstrap
		b.Bootstrap = &bootstrap
		bootstrap.Supervisor, err = read(bootstrap.SupervisorSHA256)
		if err != nil {
			return b, err
		}
		bootstrap.Policy, err = read(bootstrap.PolicySHA256)
		if err != nil {
			return b, err
		}
		if bootstrap.HostRecovery != nil {
			h := *bootstrap.HostRecovery
			bootstrap.HostRecovery = &h
			h.MACHooks = append([]MACHookBootstrap(nil), h.MACHooks...)
			if err = h.payloads(func(hash string, p *[]byte, limit uint64) error {
				data, e := read(hash)
				if e != nil {
					return e
				}
				if uint64(len(data)) > limit {
					return fmt.Errorf("host payload too large")
				}
				*p = data
				return nil
			}); err != nil {
				return b, err
			}
			if err = h.Validate(true); err != nil {
				return b, err
			}
		}
	}
	return b, nil
}
