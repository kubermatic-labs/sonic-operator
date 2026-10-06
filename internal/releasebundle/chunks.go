// SPDX-License-Identifier: Apache-2.0
package releasebundle

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

type Metadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
}
type ConfigMap struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   `json:"metadata"`
	Immutable  bool              `json:"immutable"`
	BinaryData map[string][]byte `json:"binaryData"`
}
type Chunk struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}
type Source struct {
	SHA256 string  `json:"sha256"`
	Size   int     `json:"size"`
	Chunks []Chunk `json:"chunks"`
}

func ChunkSource(slot string, data []byte) (Source, []ConfigMap, error) {
	limit := 0
	switch slot {
	case "AgentBinary", "SupervisorBinary", "HostRecoveryBinary":
		limit = 96 << 20
	case "HostProfile":
		limit = 256 << 10
	case "Policy", "ImportedHelper", "ImportedHook":
		limit = 64 << 10
	}
	if limit == 0 || len(data) == 0 || len(data) > limit {
		return Source{}, nil, fmt.Errorf("public source slot or size rejected")
	}
	s := Source{SHA256: artifact.Digest(data), Size: len(data)}
	var objects []ConfigMap
	for start := 0; start < len(data); start += artifact.ChunkBytes {
		end := min(start+artifact.ChunkBytes, len(data))
		raw := data[start:end]
		hash := artifact.Digest(raw)
		digest, _ := hex.DecodeString(hash)
		name := "sa-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest))
		s.Chunks = append(s.Chunks, Chunk{Name: name, Key: "content", SHA256: hash, Size: len(raw)})
		objects = append(objects, ConfigMap{APIVersion: "v1", Kind: "ConfigMap", Metadata: Metadata{Name: name}, Immutable: true, BinaryData: map[string][]byte{"content": raw}})
	}
	return s, objects, nil
}

func ValidateChunks(s Source, objects []ConfigMap) error {
	if len(s.Chunks) == 0 || len(s.Chunks) != len(objects) || s.Size > artifact.MaxBundleBytes {
		return fmt.Errorf("invalid chunk sources")
	}
	var data []byte
	for i, c := range s.Chunks {
		cm := objects[i]
		raw := cm.BinaryData[c.Key]
		if !cm.Immutable || cm.UID != "" || cm.Name != c.Name || c.Key != "content" || c.Size <= 0 || c.Size > artifact.ChunkBytes || len(raw) != c.Size || artifact.Digest(raw) != c.SHA256 {
			return fmt.Errorf("chunk source identity mismatch")
		}
		data = append(data, raw...)
	}
	if len(data) != s.Size || artifact.Digest(data) != s.SHA256 {
		return fmt.Errorf("ordered source hash mismatch")
	}
	return nil
}
