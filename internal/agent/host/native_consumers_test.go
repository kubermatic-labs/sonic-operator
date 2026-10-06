// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"os"
	"testing"
)

func TestNativeConsumerIdentityIsRequiredBeyondTemplateEquality(t *testing.T) {
	n := &Native{ReadFile: func(string) ([]byte, error) { return []byte("installed startup consumer"), nil }}
	p := NativeProfile{ConsumerSHA256: map[string]string{"interfaces-generator": digestForTest("installed startup consumer")}}
	if err := n.verifyConsumers(context.Background(), p, "Management"); err != nil {
		t.Fatal(err)
	}
	p.ConsumerSHA256["interfaces-generator"] = digestForTest("different consumer")
	if n.verifyConsumers(context.Background(), p, "Management") == nil {
		t.Fatal("template equality masked a changed native generator")
	}
	if n.verifyConsumers(context.Background(), NativeProfile{}, "Management") == nil {
		t.Fatal("missing consumer qualification accepted")
	}
	n.ReadFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if n.verifyConsumers(context.Background(), p, "Management") == nil {
		t.Fatal("absent consumer qualified")
	}
}
