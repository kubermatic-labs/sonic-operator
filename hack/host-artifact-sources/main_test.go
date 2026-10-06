// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	"github.com/ironcore-dev/sonic-operator/internal/releasebundle"
)

func TestChunkSourcesImmutableOrderedAndUnbound(t *testing.T) {
	data := bytes.Repeat([]byte{1, 2, 3}, 200000)
	refs, objects, err := releasebundle.ChunkSource("AgentBinary", data)
	if err != nil {
		t.Fatal(err)
	}
	var joined []byte
	for i, r := range refs.Chunks {
		cm := objects[i]
		if !cm.Immutable || cm.UID != "" || cm.Name != r.Name || len(cm.BinaryData["content"]) > artifact.ChunkBytes {
			t.Fatal("unqualified source object")
		}
		raw := cm.BinaryData["content"]
		if artifact.Digest(raw) != r.SHA256 {
			t.Fatal("chunk hash mismatch")
		}
		joined = append(joined, raw...)
	}
	if !bytes.Equal(data, joined) || refs.SHA256 != artifact.Digest(data) {
		t.Fatal("ordered source identity mismatch")
	}
	refs.Chunks[0], refs.Chunks[1] = refs.Chunks[1], refs.Chunks[0]
	if releasebundle.ValidateChunks(refs, objects) == nil {
		t.Fatal("wrong chunk order accepted")
	}
}

func TestSourceSecretAndAggregateBounds(t *testing.T) {
	for _, slot := range []string{"AgentKey", "AgentCertificate", "AgentCA", "SNMP", "unknown"} {
		if _, _, err := releasebundle.ChunkSource(slot, []byte("private")); err == nil {
			t.Fatal("secret/unknown slot exported", slot)
		}
	}
	if releasebundle.CheckAggregate([]int64{96 << 20, 33 << 20}) == nil {
		t.Fatal("aggregate overflow accepted")
	}
	if err := releasebundle.CheckAggregate([]int64{96 << 20, 32 << 20}); err != nil {
		t.Fatal(err)
	}
}
