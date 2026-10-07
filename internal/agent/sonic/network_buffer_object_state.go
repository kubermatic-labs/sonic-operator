// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"strings"
)

// There is no qualified read-only export of m_buffer_type_maps/m_qos_maps and
// pending-removal lifecycle in the inspected SONiC. In particular, neither an
// executable hash nor a currently bound equal-valued object supplies it.
const bufferObjectStateUnavailable = "native consumer name/OID and pending-removal lifecycle acknowledgement unavailable; producer instrumentation is required"

// Test-only transport seam for a hypothetical independently instrumented
// producer. It is not an RPC field or a claimed existing SONiC table/endpoint.
type bufferObjectReaderKey struct{}
type bufferObjectReader func(context.Context, string, string) (map[string]string, error)

func (r qosRedisRead) bufferObject(ctx context.Context, table, name string) (map[string]string, error) {
	if read, ok := ctx.Value(bufferObjectReaderKey{}).(bufferObjectReader); ok {
		return read(ctx, table, name)
	}
	return nil, fmt.Errorf("%s", bufferObjectStateUnavailable)
}

func bufferObjectKey(key string) (string, string, bool) {
	table, name, ok := strings.Cut(strings.TrimPrefix(key, "CONSUMER_OBJECT|"), "|")
	return table, name, ok && strings.HasPrefix(key, "CONSUMER_OBJECT|") && qosNamePattern.MatchString(name) && (table == "BUFFER_POOL" || table == "BUFFER_PROFILE" || table == "TC_TO_PRIORITY_GROUP_MAP")
}

func (b *bufferDiscovery) namedObject(table, name string) (string, error) {
	key := "CONSUMER_OBJECT|" + table + "|" + name
	state, err := bufferReadHash(b.ctx, b.read, "NATIVE", key)
	if err != nil {
		return "", err
	}
	if !qosValidOID(state["oid"]) || state["pending_remove"] != "false" || state["lifecycle"] == "" || len(state) != 3 {
		return "", fmt.Errorf("consumer object %s/%s is unacknowledged or pending native deletion; non-disruptive cancellation is unqualified", table, name)
	}
	if err := b.check("NATIVE", key, state, true, nil); err != nil {
		return "", err
	}
	return state["oid"], nil
}
