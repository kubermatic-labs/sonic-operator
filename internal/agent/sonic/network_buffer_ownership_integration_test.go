//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func bufferCapturedRequest(t *testing.T, key string, row map[string]string) *agent.NetworkRequest {
	t.Helper()
	table, name, _ := strings.Cut(key, "|")
	kind := ""
	spec := map[string]any{}
	switch table {
	case "BUFFER_POOL":
		kind = "BufferPool"
		spec["name"] = name
		spec["type"] = row["type"]
		spec["mode"] = row["mode"]
	case "BUFFER_PROFILE":
		kind = "BufferProfile"
		spec["name"] = name
		spec["pool"] = row["pool"]
	case "BUFFER_PG", "BUFFER_QUEUE":
		kind = "BufferPG"
		if table == "BUFFER_QUEUE" {
			kind = "BufferQueue"
		}
		port, selector, _ := strings.Cut(name, "|")
		spec["interfaceName"] = port
		spec["range"] = selector
		spec["profile"] = row["profile"]
	case "PORT_QOS_MAP":
		kind = "QoSBinding"
		spec["interfaceName"] = name
		spec["tcToPriorityGroup"] = row["tc_to_pg_map"]
	case "TC_TO_PRIORITY_GROUP_MAP":
		kind = "QoSMap"
		spec["name"] = name
		spec["type"] = "TCToPriorityGroup"
		entries := []map[string]int{}
		for from, to := range row {
			f, _ := strconv.Atoi(from)
			v, _ := strconv.Atoi(to)
			entries = append(entries, map[string]int{"from": f, "to": v})
		}
		spec["entries"] = entries
	}
	if table == "BUFFER_POOL" || table == "BUFFER_PROFILE" {
		for field, public := range map[string]string{"size": "size", "xoff": "xoff", "xon": "xon", "xon_offset": "xonOffset", "dynamic_th": "dynamicThreshold", "static_th": "staticThreshold"} {
			if value, ok := row[field]; ok {
				v, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				spec[public] = v
			}
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return &agent.NetworkRequest{Kind: kind, OwnerID: "buffer-owner", Spec: raw}
}

func bufferCapturedEngine(t *testing.T, host string) (*SonicAgent, map[string]vlanChangeDB, *int) {
	t.Helper()
	raw, err := os.ReadFile("testdata/buffer-ownership/native/" + host + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var capture map[string]vlanChangeDB
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	m, _, _, saves := networkEngineFixture(t)
	// CONDITIONAL contract test, not native qualification: independent producer
	// name/lifecycle instrumentation does not exist on the inspected SONiC.
	// Explicit synthetic associations are never derived from the bound objects.
	objects := map[string]string{}
	if host == "core-01" {
		objects = map[string]string{"BUFFER_POOL|PORT3_INGRESS_POOL": bufferPoolOID, "BUFFER_PROFILE|PORT3_INGRESS_PROFILE": bufferProfileOID}
	} else {
		objects = map[string]string{"BUFFER_POOL|egress_lossless_pool": "oid:0x180000000006ce", "BUFFER_POOL|egress_lossy_pool": "oid:0x180000000006cf", "BUFFER_POOL|ingress_lossless_pool": "oid:0x180000000006d0", "BUFFER_PROFILE|egress_lossless_profile": "oid:0x190000000006d1", "BUFFER_PROFILE|egress_lossy_profile": "oid:0x190000000006d2", "BUFFER_PROFILE|ingress_lossy_profile": "oid:0x190000000006d3", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY": "oid:0x140000000006ee"}
		if host == "leaf-05" {
			objects["TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"] = "oid:0x140000000006ec"
		}
	}
	consumer, _ := json.Marshal(capture["NATIVE"]["BUFFER_CONSUMER"])
	withConsumer := func(ctx context.Context) context.Context {
		ctx = context.WithValue(ctx, bufferObjectReaderKey{}, bufferObjectReader(func(_ context.Context, table, name string) (map[string]string, error) {
			oid, ok := objects[table+"|"+name]
			if !ok {
				return nil, fmt.Errorf("missing synthetic independent producer object")
			}
			return map[string]string{"oid": oid, "pending_remove": "false", "lifecycle": "test-create-1"}, nil
		}))
		return context.WithValue(ctx, bufferConsumerRunnerKey{}, bufferConsumerRunner(func(cmd *exec.Cmd) ([]byte, error) {
			if len(cmd.Args) != 6 || cmd.Args[0] != "docker" || cmd.Args[1] != "exec" || cmd.Args[2] != "swss" || cmd.Args[3] != "python3" || cmd.Args[4] != "-c" || cmd.Args[5] != bufferConsumerScript {
				t.Fatalf("unexpected native probe argv: %v", cmd.Args)
			}
			return consumer, nil
		}))
	}
	m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		p, err := planNetworkResource(db, r)
		if err != nil {
			return nil, err
		}
		preflight, runtime := p.Preflight, p.Runtime
		p.Preflight = func(ctx context.Context, m *SonicAgent) error { return preflight(withConsumer(ctx), m) }
		p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
			return runtime(withConsumer(ctx), m)
		}
		return p, nil
	}
	for database, rows := range capture {
		if database == "NATIVE" {
			continue
		}
		db := m.clientPool[database]
		if db == nil {
			db = newVLANRedis(t)
			m.clientPool[database] = db
		}
		for key, fields := range rows {
			if len(fields) > 0 {
				if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return m, capture, saves
}

func TestNetworkBufferQualifiedOwnershipRepair(t *testing.T) {
	for _, tc := range []struct{ host, key, field, native, attribute string }{
		{"core-01", "BUFFER_POOL|PORT3_INGRESS_POOL", "size", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:" + bufferPoolOID, "SAI_BUFFER_POOL_ATTR_SIZE"},
		{"core-01", "BUFFER_PROFILE|PORT3_INGRESS_PROFILE", "dynamic_th", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:" + bufferProfileOID, "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH"},
		{"core-01", "BUFFER_PG|Ethernet11|7", "profile", "ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:" + bufferPGOID, "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE"},
		{"leaf-03", "BUFFER_QUEUE|Ethernet11|0-2", "profile", "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:oid:0x150000000006ac", "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID"},
		{"leaf-03", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", "0", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:0x140000000006ee", "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"},
		{"leaf-03", "PORT_QOS_MAP|Ethernet11", "tc_to_pg_map", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:" + bufferPortOID, "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			m, capture, saves := bufferCapturedEngine(t, tc.host)
			db := m.clientPool["CONFIG_DB"]
			asic := m.clientPool["ASIC_DB"]
			req := bufferCapturedRequest(t, tc.key, capture["CONFIG_DB"][tc.key])
			got, st := m.EnsureNetworkResource(t.Context(), req)
			if st != nil || !got.RuntimeVerified || !got.PersistenceVerified || *saves != 1 {
				t.Fatalf("native adoption: %+v %v saves=%d", got, st, *saves)
			}
			foreign := *req
			foreign.OwnerID = "other"
			if _, st := m.EnsureNetworkResource(t.Context(), &foreign); st == nil {
				t.Fatal("adopted ownership transferred")
			}
			if err := db.HSet(t.Context(), tc.key, tc.field, "drift").Err(); err != nil {
				t.Fatal(err)
			}
			changedNative := "drift"
			if tc.attribute == bufferMapListAttr {
				var mapping map[string]any
				if err := json.Unmarshal([]byte(capture["ASIC_DB"][tc.native][tc.attribute]), &mapping); err != nil {
					t.Fatal(err)
				}
				mapping["list"].([]any)[0].(map[string]any)["value"].(map[string]any)["pg"] = 1
				raw, err := json.Marshal(mapping)
				if err != nil {
					t.Fatal(err)
				}
				changedNative = string(raw)
			}
			if err := asic.HSet(t.Context(), tc.native, tc.attribute, changedNative).Err(); err != nil {
				t.Fatal(err)
			}
			got, st = m.EnsureNetworkResource(t.Context(), req)
			unsupported := req.Kind == "BufferPG" || req.Kind == "BufferQueue"
			if (st != nil) != unsupported || got.BufferRepairEligible == unsupported || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified || *saves != 2 {
				t.Fatalf("repair must persist without inferring asynchronous runtime: %+v %v saves=%d", got, st, *saves)
			}
			if db.HGet(t.Context(), tc.key, tc.field).Val() != capture["CONFIG_DB"][tc.key][tc.field] {
				t.Fatal("owned drift was not restored")
			}
			if err := asic.HSet(t.Context(), tc.native, tc.attribute, capture["ASIC_DB"][tc.native][tc.attribute]).Err(); err != nil {
				t.Fatal(err)
			}
			got, st = m.EnsureNetworkResource(t.Context(), req)
			if st != nil || !got.RuntimeVerified || *saves != 2 {
				t.Fatalf("consumer convergence: %+v %v", got, st)
			}
			// The native identity fingerprint survives restart and fences a re-created
			// object even if its values happen to be equal.
			restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: m.clientPool, planNetwork: m.planNetwork, saveConfig: func(context.Context) *agent.Status { t.Fatal("changed identity saved"); return nil }}
			oid := strings.TrimPrefix(tc.native, strings.Join(strings.SplitN(tc.native, ":", 3)[:2], ":")+":")
			if err := asic.HSet(t.Context(), "VIDTORID", oid, "oid:0x999").Err(); err != nil {
				t.Fatal(err)
			}
			if _, st := restarted.EnsureNetworkResource(t.Context(), req); st == nil {
				t.Fatal("replacement native identity accepted")
			}
		})
	}
}

type bufferCASPayloadHook struct {
	redis.Hook
	payloads []string
}

func (h *bufferCASPayloadHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *bufferCASPayloadHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *bufferCASPayloadHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && cmd.Args()[1] == vlanChangeCASScript {
			h.payloads = append(h.payloads, cmd.Args()[4].(string))
		}
		return next(ctx, cmd)
	}
}

func TestNetworkBufferRuntimeOnlyRepairAndPendingSave(t *testing.T) {
	m, capture, _ := bufferCapturedEngine(t, "core-01")
	key := "BUFFER_PROFILE|PORT3_INGRESS_PROFILE"
	req := bufferCapturedRequest(t, key, capture["CONFIG_DB"][key])
	if _, st := m.EnsureNetworkResource(t.Context(), req); st != nil {
		t.Fatal(st)
	}
	db, asic := m.clientPool["CONFIG_DB"], m.clientPool["ASIC_DB"]
	native := "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:" + bufferProfileOID
	attribute := "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH"
	if err := asic.HSet(t.Context(), native, attribute, "2").Err(); err != nil {
		t.Fatal(err)
	}
	hook := &bufferCASPayloadHook{}
	db.AddHook(hook)
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "interrupted save"} }
	got, st := m.EnsureNetworkResource(t.Context(), req)
	if st == nil || !got.ConfigurationVerified || got.PersistenceVerified || len(hook.payloads) != 1 || !strings.Contains(hook.payloads[0], "PORT3_INGRESS_PROFILE") {
		t.Fatalf("runtime-only repair did not emit qualified HSET: %+v %v payloads=%v", got, st, hook.payloads)
	}
	if err := asic.HSet(t.Context(), native, attribute, "3").Err(); err != nil {
		t.Fatal(err)
	}
	// Recovery must use the old recorded profile and must not re-emit a successful
	// CAS merely because persistence was interrupted afterwards.
	req.Spec = json.RawMessage(`{"name":"PORT3_INGRESS_PROFILE","pool":"edited-after-interruption","size":0,"dynamicThreshold":7}`)
	m.saveConfig = func(context.Context) *agent.Status { return nil }
	got, st = m.RecoverNetworkResource(t.Context(), req)
	if st != nil || !got.PersistenceVerified || !got.RuntimeVerified || len(hook.payloads) != 1 {
		t.Fatalf("pending recovery: %+v %v calls=%d", got, st, len(hook.payloads))
	}
	if !maps.Equal(db.HGetAll(t.Context(), key).Val(), capture["CONFIG_DB"][key]) {
		t.Fatal("profile changed during recovery")
	}
	req = bufferCapturedRequest(t, key, capture["CONFIG_DB"][key])
	if err := db.Del(t.Context(), key).Err(); err != nil {
		t.Fatal(err)
	}
	got, st = m.EnsureNetworkResource(t.Context(), req)
	if st == nil || !strings.Contains(st.Message, "DEL cancellation") || db.Exists(t.Context(), key).Val() != 0 {
		t.Fatalf("unqualified deleted-row repair was permitted: %+v %v", got, st)
	}
}

func TestNetworkBufferBindingRuntimeOnlyRequiresConsumerRepair(t *testing.T) {
	for _, tc := range []struct{ host, key, native, attr string }{
		{"core-01", "BUFFER_PG|Ethernet11|7", "ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:" + bufferPGOID, "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE"},
		{"leaf-03", "BUFFER_QUEUE|Ethernet11|0-2", "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:oid:0x150000000006ac", "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			m, capture, saves := bufferCapturedEngine(t, tc.host)
			req := bufferCapturedRequest(t, tc.key, capture["CONFIG_DB"][tc.key])
			if _, st := m.EnsureNetworkResource(t.Context(), req); st != nil {
				t.Fatal(st)
			}
			if err := m.clientPool["ASIC_DB"].HSet(t.Context(), tc.native, tc.attr, "oid:0x999").Err(); err != nil {
				t.Fatal(err)
			}
			hook := &bufferCASPayloadHook{}
			m.clientPool["CONFIG_DB"].AddHook(hook)
			blocked, st := m.EnsureNetworkResource(t.Context(), req)
			if st == nil || !strings.Contains(st.Message, "deduplicates unchanged") || !blocked.PersistenceVerified || !blocked.ConfigurationVerified || blocked.BufferRepairEligible || *saves != 1 || len(hook.payloads) != 0 {
				t.Fatalf("ineffective native repair attempted: %v saves=%d payloads=%v", st, *saves, hook.payloads)
			}
			if err := m.clientPool["ASIC_DB"].HSet(t.Context(), tc.native, tc.attr, capture["ASIC_DB"][tc.native][tc.attr]).Err(); err != nil {
				t.Fatal(err)
			}
			if err := m.clientPool["CONFIG_DB"].Del(t.Context(), tc.key).Err(); err != nil {
				t.Fatal(err)
			}
			got, st := m.EnsureNetworkResource(t.Context(), req)
			if st == nil || !strings.Contains(st.Message, "DEL cancellation") || m.clientPool["CONFIG_DB"].Exists(t.Context(), tc.key).Val() != 0 {
				t.Fatalf("unqualified binding deletion repair: %+v %v", got, st)
			}
		})
	}
}
