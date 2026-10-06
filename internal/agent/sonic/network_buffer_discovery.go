// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
)

type bufferDiscovery struct {
	ctx    context.Context
	read   qosRead
	config vlanChangeDB
	proof  *bufferNativeProof
}

func bufferDiscover(ctx context.Context, read qosRead, desired vlanChangeDB) (*bufferNativeProof, error) {
	config, err := read.configSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !networkSubset(config, desired) {
		return nil, fmt.Errorf("buffer adoption requires existing equal configuration; new values are not qualified")
	}
	b := &bufferDiscovery{ctx: ctx, read: read, config: config, proof: &bufferNativeProof{Version: 2, Desired: desired}}
	meta := config["DEVICE_METADATA|localhost"]
	if meta["buffer_model"] != "traditional" || meta["platform"] == "" || meta["hwsku"] == "" {
		return nil, fmt.Errorf("buffer qualification requires identified traditional buffer manager platform")
	}
	if err := b.check("NATIVE", "BUFFER_CONSUMER", bufferConsumerBuild, true, nil); err != nil {
		return nil, err
	}
	if err := b.check("CONFIG_DB", "DEVICE_METADATA|localhost", map[string]string{"buffer_model": "traditional", "platform": meta["platform"], "hwsku": meta["hwsku"]}, false, nil); err != nil {
		return nil, err
	}
	for key := range desired {
		table, name, _ := strings.Cut(key, "|")
		switch table {
		case "BUFFER_POOL":
			_, err = b.pool(name)
		case "BUFFER_PROFILE":
			err = b.profile(name, "")
		case "TC_TO_PRIORITY_GROUP_MAP":
			err = b.qosMap(name, "")
		case "PORT_QOS_MAP":
			err = b.qosMap(config[key]["tc_to_pg_map"], name)
		case "BUFFER_PG", "BUFFER_QUEUE":
			var oids []string
			oids, err = b.binding(key)
			if err == nil {
				for _, oid := range oids {
					if err = b.profile(config[key]["profile"], oid); err != nil {
						break
					}
				}
			}
		default:
			err = fmt.Errorf("unsupported native buffer qualification table")
		}
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(b.proof.Checks, func(a, c bufferNativeCheck) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(c)
		return strings.Compare(string(x), string(y))
	})
	b.proof.Fingerprint = b.proof.digest()
	// Evidence is not a single Redis transaction. Recheck every recorded edge
	// before accepting it; the network engine separately CASes full CONFIG_DB.
	if err := bufferVerify(ctx, read, b.proof, false); err != nil {
		return nil, err
	}
	return b.proof, nil
}

func (b *bufferDiscovery) check(db, key string, want map[string]string, exact bool, repair []string) error {
	row, err := bufferReadHash(b.ctx, b.read, db, key)
	if err != nil {
		return err
	}
	actual, err := bufferNormalizeChecked(key, row)
	if err != nil {
		return err
	}
	expected, err := bufferNormalizeChecked(key, want)
	if err != nil {
		return err
	}
	if len(row) == 0 || !networkSubset(vlanChangeDB{key: actual}, vlanChangeDB{key: expected}) || (exact && !maps.Equal(actual, expected)) {
		return fmt.Errorf("native buffer evidence missing or different at %s/%s", db, key)
	}
	b.proof.Checks = append(b.proof.Checks, bufferNativeCheck{DB: db, Key: key, Fields: expected, Exact: exact, RepairFields: repair})
	return nil
}

func (b *bufferDiscovery) configured(key string) error {
	row := b.config[key]
	if len(row) == 0 {
		return fmt.Errorf("missing native dependency %s", key)
	}
	repair := []string{}
	for f := range b.proof.Desired[key] {
		repair = append(repair, f)
	}
	slices.Sort(repair)
	if err := b.check("CONFIG_DB", key, row, true, repair); err != nil {
		return err
	}
	table, name, _ := strings.Cut(key, "|")
	if strings.HasPrefix(table, "BUFFER_") {
		return b.check("APPL_DB", table+"_TABLE:"+strings.ReplaceAll(name, "|", ":"), row, true, repair)
	}
	return nil
}

func (b *bufferDiscovery) translated(oid string) error {
	if !qosValidOID(oid) {
		return fmt.Errorf("native buffer OID absent or invalid")
	}
	ids, err := b.read.hash(b.ctx, "ASIC_DB", "VIDTORID")
	if err != nil {
		return err
	}
	if !qosValidOID(ids[oid]) {
		return fmt.Errorf("native buffer OID is untranslated")
	}
	return b.check("ASIC_DB", "VIDTORID", map[string]string{oid: ids[oid]}, false, nil)
}

func (b *bufferDiscovery) pool(name string) (string, error) {
	consumerOID, err := b.namedObject("BUFFER_POOL", name)
	if err != nil {
		return "", err
	}
	key := "BUFFER_POOL|" + name
	row := b.config[key]
	if err := bufferValidatePool(row); err != nil {
		return "", err
	}
	if err := b.configured(key); err != nil {
		return "", err
	}
	names, err := b.read.hash(b.ctx, "COUNTERS_DB", "COUNTERS_BUFFER_POOL_NAME_MAP")
	if err != nil {
		return "", err
	}
	oid := names[name]
	if oid != consumerOID {
		return "", fmt.Errorf("pool counter OID disagrees with independent consumer name identity")
	}
	if err := b.translated(oid); err != nil {
		return "", err
	}
	if err := b.check("COUNTERS_DB", "COUNTERS_BUFFER_POOL_NAME_MAP", map[string]string{name: oid}, false, nil); err != nil {
		return "", err
	}
	attrs := map[string]string{"SAI_BUFFER_POOL_ATTR_TYPE": "SAI_BUFFER_POOL_TYPE_" + strings.ToUpper(row["type"]), "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE": "SAI_BUFFER_POOL_THRESHOLD_MODE_" + strings.ToUpper(row["mode"]), "SAI_BUFFER_POOL_ATTR_SIZE": row["size"]}
	if row["xoff"] != "" {
		attrs["SAI_BUFFER_POOL_ATTR_XOFF_SIZE"] = row["xoff"]
	}
	repair := []string{}
	for field, attr := range map[string]string{"size": "SAI_BUFFER_POOL_ATTR_SIZE", "xoff": "SAI_BUFFER_POOL_ATTR_XOFF_SIZE"} {
		if _, ok := b.proof.Desired[key][field]; ok {
			repair = append(repair, attr)
		}
	}
	slices.Sort(repair)
	err = b.check("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:"+oid, attrs, true, repair)
	return oid, err
}

func (b *bufferDiscovery) topology(table, port, index string) (string, map[string]string, error) {
	ports, err := b.read.hash(b.ctx, "COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
	if err != nil {
		return "", nil, err
	}
	portOID := ports[port]
	if err := b.translated(portOID); err != nil {
		return "", nil, err
	}
	if err := b.check("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP", map[string]string{port: portOID}, false, nil); err != nil {
		return "", nil, err
	}
	kind, typ := "PG", "INGRESS_PRIORITY_GROUP"
	if table == "BUFFER_QUEUE" {
		kind, typ = "QUEUE", "QUEUE"
	}
	names, err := b.read.hash(b.ctx, "COUNTERS_DB", "COUNTERS_"+kind+"_NAME_MAP")
	if err != nil {
		return "", nil, err
	}
	oid := names[port+":"+index]
	if err := b.translated(oid); err != nil {
		return "", nil, err
	}
	for key, fields := range map[string]map[string]string{"COUNTERS_" + kind + "_NAME_MAP": {port + ":" + index: oid}, "COUNTERS_" + kind + "_INDEX_MAP": {oid: index}, "COUNTERS_" + kind + "_PORT_MAP": {oid: portOID}} {
		if err := b.check("COUNTERS_DB", key, fields, false, nil); err != nil {
			return "", nil, err
		}
	}
	key := "ASIC_STATE:SAI_OBJECT_TYPE_" + typ + ":" + oid
	attrs, err := b.read.hash(b.ctx, "ASIC_DB", key)
	if err != nil {
		return "", nil, err
	}
	if len(attrs) == 0 {
		return "", nil, fmt.Errorf("native PG/queue absent")
	}
	b.proof.Checks = append(b.proof.Checks, bufferNativeCheck{DB: "ASIC_DB", Key: key, Fields: map[string]string{}, Presence: true})
	if typ == "QUEUE" {
		if attrs["SAI_QUEUE_ATTR_TYPE"] != "SAI_QUEUE_TYPE_UNICAST" && attrs["SAI_QUEUE_ATTR_TYPE"] != "SAI_QUEUE_TYPE_MULTICAST" {
			return "", nil, fmt.Errorf("unsupported native queue type")
		}
		if err := b.check("ASIC_DB", key, map[string]string{"SAI_QUEUE_ATTR_TYPE": attrs["SAI_QUEUE_ATTR_TYPE"], "SAI_QUEUE_ATTR_INDEX": index}, false, nil); err != nil {
			return "", nil, err
		}
	}
	return key, attrs, nil
}

func (b *bufferDiscovery) binding(key string) ([]string, error) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("unsupported native buffer selector")
	}
	if err := b.configured(key); err != nil {
		return nil, err
	}
	if err := bufferSelectors(b.config, key); err != nil {
		return nil, err
	}
	max := uint64(7)
	attr := "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE"
	if parts[0] == "BUFFER_QUEUE" {
		max = 255
		attr = "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID"
	}
	lo, hi, err := api.BufferRange(parts[2], max)
	if err != nil {
		return nil, err
	}
	var profiles []string
	for index := lo; index <= hi; index++ {
		native, attrs, err := b.topology(parts[0], parts[1], qosUint(index))
		if err != nil {
			return nil, err
		}
		oid := attrs[attr]
		if err := b.translated(oid); err != nil {
			return nil, err
		}
		repair := []string{}
		if _, ok := b.proof.Desired[key]["profile"]; ok {
			repair = append(repair, attr)
		}
		if err := b.check("ASIC_DB", native, map[string]string{attr: oid}, false, repair); err != nil {
			return nil, err
		}
		profiles = append(profiles, oid)
	}
	return profiles, nil
}

func (b *bufferDiscovery) profile(name, oid string) error {
	consumerOID, err := b.namedObject("BUFFER_PROFILE", name)
	if err != nil {
		return err
	}
	if oid != "" && oid != consumerOID {
		return fmt.Errorf("bound profile OID disagrees with independent consumer name identity")
	}
	key := "BUFFER_PROFILE|" + name
	row := b.config[key]
	if err := bufferValidateProfile(b.config, row, ""); err != nil {
		return err
	}
	if err := b.configured(key); err != nil {
		return err
	}
	poolOID, err := b.pool(row["pool"])
	if err != nil {
		return err
	}
	if oid == "" {
		keys := []string{}
		for k, r := range b.config {
			if (strings.HasPrefix(k, "BUFFER_PG|") || strings.HasPrefix(k, "BUFFER_QUEUE|")) && r["profile"] == name {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		if len(keys) == 0 {
			return fmt.Errorf("buffer profile requires a native PG/queue binding anchor; equal unbound ASIC content is insufficient")
		}
		for _, key := range keys {
			oids, err := b.binding(key)
			if err != nil {
				return err
			}
			for _, other := range oids {
				if other != consumerOID {
					return fmt.Errorf("binding disagrees with independent profile name identity")
				}
			}
		}
	}
	oid = consumerOID
	if err := b.translated(oid); err != nil {
		return err
	}
	attrs := map[string]string{"SAI_BUFFER_PROFILE_ATTR_POOL_ID": poolOID, "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE": row["size"]}
	fields := map[string]string{"size": "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE", "dynamic_th": "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH", "static_th": "SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH", "xon": "SAI_BUFFER_PROFILE_ATTR_XON_TH", "xoff": "SAI_BUFFER_PROFILE_ATTR_XOFF_TH", "xon_offset": "SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH"}
	mode := "STATIC"
	if _, ok := row["dynamic_th"]; ok {
		mode = "DYNAMIC"
	}
	attrs["SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE"] = "SAI_BUFFER_PROFILE_THRESHOLD_MODE_" + mode
	repair := []string{}
	for field, attr := range fields {
		if v, ok := row[field]; ok {
			attrs[attr] = v
		}
		if _, ok := b.proof.Desired[key][field]; ok {
			repair = append(repair, attr)
		}
	}
	slices.Sort(repair)
	return b.check("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"+oid, attrs, true, repair)
}
