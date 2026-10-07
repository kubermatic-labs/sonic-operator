// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// savedPortConfig reads independent boot-persistence evidence, never Redis or
// the save command's response. Only port tables are decoded; unrelated tables
// may contain credentials or values with a different schema.
func (m *SonicAgent) savedPortConfig() (vlanChangeDB, error) {
	read := m.readSavedPortConfig
	if read == nil {
		read = func() ([]byte, error) {
			f, err := os.Open("/etc/sonic/config_db.json")
			if err != nil {
				return nil, err
			}
			defer func() { _ = f.Close() }()
			const maxSize = 32 << 20
			data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
			if len(data) > maxSize {
				return nil, fmt.Errorf("saved configuration exceeds size limit")
			}
			return data, err
		}
	}
	data, err := read()
	if err != nil {
		return nil, fmt.Errorf("cannot read saved port configuration")
	}
	var tables map[string]json.RawMessage
	if json.Unmarshal(data, &tables) != nil || tables == nil {
		return nil, fmt.Errorf("invalid saved configuration JSON")
	}
	out := vlanChangeDB{}
	for _, table := range []string{"PORT", "BREAKOUT_CFG"} {
		if raw, ok := tables[table]; ok {
			var rows map[string]map[string]string
			if json.Unmarshal(raw, &rows) != nil || rows == nil {
				return nil, fmt.Errorf("invalid saved %s table", table)
			}
			for key, fields := range rows {
				out[table+"|"+key] = fields
			}
		}
	}
	return out, nil
}

func (m *SonicAgent) adminPersisted(port, desired string) bool {
	saved, err := m.savedPortConfig()
	return err == nil && saved["PORT|"+port]["admin_status"] == desired
}
