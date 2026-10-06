// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func digestForTest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func TestNativeEmptyRedisHashesMatchSONiCSavedRepresentation(t *testing.T) {
	n := &Native{ReadFile: func(string) ([]byte, error) { return []byte(`{"NTP_SERVER":{"10.0.0.1":{}}}`), nil }}
	db, e := n.saved()
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(db["NTP_SERVER"]["10.0.0.1"], map[string]string{"NULL": "NULL"}) {
		t.Fatal("SONiC empty hash normalization prevents persistence proof")
	}
}
func TestNativeBootMACRestoresPolicyRoutesAfterLinkCycle(t *testing.T) {
	var commands []string
	n := &Native{ReadFile: func(path string) ([]byte, error) {
		switch path {
		case bootFile:
			return []byte(`{"mac":"02:00:00:00:00:11"}`), nil
		case "/etc/sonic/config_db.json":
			return []byte(`{"MGMT_INTERFACE":{"eth0|10.0.0.11/24":{"gwaddr":"10.0.0.1"}}}`), nil
		}
		return nil, os.ErrNotExist
	}, Run: func(_ context.Context, args []string, _ []byte) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		if reflect.DeepEqual(args, []string{"ip", "-j", "address", "show", "dev", "eth0"}) {
			return []byte(`[{"address":"00:11:22:33:44:55"}]`), nil
		}
		return nil, nil
	}}
	if err := n.ApplyBootMAC(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "route replace default via 10.0.0.1 dev eth0 table default metric 201") {
		t.Fatal("MAC down/up lost management policy routes")
	}
}
func TestNativeObservationDoesNotInferRuntimeFromMatchingRedis(t *testing.T) {
	m := validManagement()
	db := Database{"MGMT_INTERFACE": {"eth0|10.0.0.11/24": {"gwaddr": "10.0.0.1"}}}
	profile, _ := json.Marshal(NativeProfile{ImageSHA256: digestForTest("image"), InterfacesSHA256: digestForTest("template"), ConsumerSHA256: map[string]string{"interfaces-generator": digestForTest("qualified consumer")}})
	saved, _ := json.Marshal(db)
	files := map[string][]byte{profileFile: profile, "/etc/sonic/sonic_version.yml": []byte("image"), interfacesTemplate: []byte("template"), "/etc/sonic/config_db.json": saved, "/etc/network/interfaces": []byte("generated"), bootFile: []byte(`{"mac":"02:00:00:00:00:11"}`), macDropIn: []byte(macUnit)}
	files["/usr/bin/interfaces-config.sh"] = []byte("qualified consumer")
	n := &Native{Load: func(context.Context) (Database, error) { return db, nil }, ReadFile: func(path string) ([]byte, error) {
		b, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	}, Run: func(_ context.Context, args []string, _ []byte) ([]byte, error) {
		s := strings.Join(args, " ")
		switch {
		case s == "sonic-cfggen -d --print-data":
			return saved, nil
		case strings.HasPrefix(s, "sonic-cfggen"):
			return []byte("generated"), nil
		case strings.Contains(s, "address show"):
			return []byte(`[{"ifname":"eth0","address":"02:00:00:00:00:99","flags":["UP"],"addr_info":[{"local":"10.0.0.11","prefixlen":24,"scope":"global"}]}]`), nil
		case strings.Contains(s, "route show"):
			return []byte(`[]`), nil
		case strings.Contains(s, "rule show"):
			return []byte(`[]`), nil
		case strings.HasPrefix(s, "ping"):
			return nil, nil
		}
		t.Fatalf("unexpected command %s", s)
		return nil, ErrNative
	}}
	q := managementRequest()
	q.Management = &m
	result, err := n.Observe(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ConfigurationVerified || !result.PersistenceVerified || result.RuntimeVerified {
		t.Fatalf("independent evidence lost: %+v", result)
	}
}

func TestNativeRecoveryAfterRedisCASBeforeKernelDispatch(t *testing.T) {
	old := validManagement()
	candidate := validManagement()
	candidate.Addresses[0].Prefix = "10.0.0.99/24"
	db := Database{"MGMT_INTERFACE": {"eth0|10.0.0.99/24": {"gwaddr": "10.0.0.1"}}}
	n := &Native{Load: func(context.Context) (Database, error) { return db, nil }, CAS: func(_ context.Context, _, after Database) error { db = after; return nil }, Save: func(context.Context) error { return nil }, WriteFile: func(string, []byte, os.FileMode) error { return nil }, Run: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		s := strings.Join(args, " ")
		switch {
		case s == "sonic-cfggen -d --print-data":
			return []byte(`{}`), nil
		case strings.HasPrefix(s, "sonic-cfggen"):
			return []byte("generated"), nil
		case strings.Contains(s, "-j address"):
			return []byte(`[{"addr_info":[{"local":"10.0.0.11","prefixlen":24,"scope":"global"}]}]`), nil
		case strings.Contains(s, "-j rule"):
			return []byte(`[{"priority":32765,"src":"10.0.0.11","table":"default"}]`), nil
		case strings.Contains(s, "-j route"):
			return []byte(`[]`), nil
		case strings.Contains(s, "address del 10.0.0.99/24"):
			return nil, ErrNative
		}
		return nil, nil
	}}
	if err := n.applyManagement(context.Background(), Snapshot{Management: candidate, ActiveMAC: old.MAC}, old, old.MAC); err != nil {
		t.Fatal("rollback assumed kernel dispatch completed:", err)
	}
}

func TestNativeScopedRouteOutputCarriesImpliedDevice(t *testing.T) {
	// Both qualified iproute2 versions omit dev when the query filters by dev.
	n := &Native{Run: func(_ context.Context, args []string, _ []byte) ([]byte, error) {
		if args[1] == "-6" {
			return []byte(`[]`), nil
		}
		return []byte(`[{"dst":"default","gateway":"10.0.0.1","table":"default","metric":201,"flags":[]},{"dst":"10.0.0.0/24","table":"default","scope":"link","flags":[]}]`), nil
	}}
	routes, err := n.managementRoutes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addresses := []byte(`[{"ifname":"eth0","address":"02:00:00:00:00:11","flags":["UP"],"addr_info":[{"local":"10.0.0.11","prefixlen":24,"scope":"global"}]}]`)
	if !managementRuntimeMatches(validManagement(), addresses, routes) {
		t.Fatal("scoped native route output lost its implied eth0 binding")
	}
}
