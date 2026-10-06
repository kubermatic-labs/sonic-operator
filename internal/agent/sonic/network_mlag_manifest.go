// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const mlagSourceRevision = "4784cca11"

var mlagFingerprintPaths = [...]string{
	"/usr/bin/iccpd", "/usr/bin/mclagdctl", "/usr/bin/mclagsyncd", "/usr/local/yang-models/sonic-mclag.yang",
}

// SONIC_MLAG_CONSUMER_MANIFEST is agent deployment policy. It must point to a
// reviewed whitelist OUTSIDE the measured iccpd container. No file in that
// container, image label, or source-version claim grants itself support.
func mlagTrustedHashes() (map[string]string, error) {
	path := os.Getenv("SONIC_MLAG_CONSUMER_MANIFEST")
	if path == "" {
		// No build has been approved in-tree yet. An empty whitelist fails closed.
		return map[string]string{}, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("path must be absolute and clean")
	}
	// Reject symlinks and writable/non-root parents as well as unsafe files.
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 || (p == path && !info.Mode().IsRegular()) || (p != path && !info.IsDir()) {
			return nil, fmt.Errorf("%s must be root-owned, non-symlink and not group/world writable", p)
		}
		if p == "/" {
			break
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, err
	}
	return mlagParseManifest(data)
}

func mlagParseManifest(data []byte) (map[string]string, error) {
	if len(data) > 16384 {
		return nil, fmt.Errorf("manifest exceeds size limit")
	}
	var fields map[string]json.RawMessage
	if err := mlagJSON(data, &fields, false); err != nil {
		return nil, err
	}
	if len(fields) != 3 || fields["version"] == nil || fields["source"] == nil || fields["sha256"] == nil {
		return nil, fmt.Errorf("manifest requires exact version/source/sha256 fields")
	}
	var manifest struct {
		Version int               `json:"version"`
		Source  string            `json:"source"`
		SHA256  map[string]string `json:"sha256"`
	}
	if err := mlagJSON(data, &manifest, false); err != nil {
		return nil, err
	}
	if manifest.Version != 1 || manifest.Source != "sonic-net/sonic-buildimage@"+mlagSourceRevision+":src/iccpd" {
		return nil, fmt.Errorf("unsupported manifest version/source")
	}
	if len(manifest.SHA256) != len(mlagFingerprintPaths) {
		return nil, fmt.Errorf("manifest must pin exactly the four consumer/schema paths")
	}
	for _, path := range mlagFingerprintPaths {
		hash := manifest.SHA256[path]
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash {
			return nil, fmt.Errorf("invalid SHA-256 for %s", path)
		}
	}
	return manifest.SHA256, nil
}
