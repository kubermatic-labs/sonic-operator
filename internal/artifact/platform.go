// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var platformModules = map[string]string{
	"PlatformInit": "__init__.py", "PlatformChassis": "chassis.py", "PlatformComponent": "component.py", "PlatformEEPROM": "eeprom.py", "PlatformFan": "fan.py", "PlatformFanDrawer": "fan_drawer.py", "PlatformAPI": "platform.py", "PlatformPSU": "psu.py", "PlatformSFP": "sfp.py", "PlatformThermal": "thermal.py",
}

const corePlatformDir = "/usr/share/sonic/device/x86_64-dell_z9100_c2538-r0"
const coreWheel = corePlatformDir + "/sonic_platform-1.0-py3-none-any.whl"
const coreImageSHA = "0cd0ea6266506346ed0b456976bfa6ce6a6cca01f0494edf051cbe1d31a47906"

func coreDestination(slot string) string {
	if name, ok := platformModules[slot]; ok {
		return "/usr/local/lib/python3.13/dist-packages/sonic_platform/" + name
	}
	switch slot {
	case "PlatformJSON":
		return corePlatformDir + "/platform.json"
	case "PlatformWheel":
		return coreWheel
	}
	names := map[string]string{"HWSKUJSON": "hwsku.json", "PortConfig": "port_config.ini", "SAIProfile": "sai.profile", "BroadcomConfig": "dc-flex-with-sfp.config.bcm"}
	if name, ok := names[slot]; ok {
		return corePlatformDir + "/Force10-Z9100-C32/" + name
	}
	return ""
}

var ErrActivationPending = errors.New("native consumers not started yet")
var ErrPackageRepair = errors.New("package transaction repair failed")

const packageSafetyProbe = `import csv,importlib.metadata,io,pathlib,re,sys
try:
 d=importlib.metadata.distribution("sonic-platform")
except importlib.metadata.PackageNotFoundError:
 print("absent");sys.exit(0)
root=pathlib.Path(d.locate_file(""))
if str(root)!=sys.argv[1] or root.resolve()!=root: raise RuntimeError("unqualified package root")
names={"__init__","chassis","component","eeprom","fan","fan_drawer","platform","psu","sfp","thermal"}
record=d.read_text("RECORD")
if record is None: raise RuntimeError("missing uninstall record")
for row in csv.reader(io.StringIO(record)):
 if len(row)!=3: raise RuntimeError("invalid uninstall record")
 name=row[0]
 valid=name in {"sonic_platform/"+n+".py" for n in names}
 valid=valid or name in {"sonic_platform-1.0.dist-info/"+n for n in ["METADATA","WHEEL","RECORD","INSTALLER","REQUESTED","direct_url.json","top_level.txt"]}
 match=re.fullmatch(r"sonic_platform/__pycache__/([a-z_]+)\.cpython-(311|313)\.pyc",name)
 valid=valid or (match is not None and match.group(1) in names)
 if not valid: raise RuntimeError("unqualified uninstall destination")
 target=root/name
 if target.resolve()!=target: raise RuntimeError("untrusted package link")
print("true")`

// This qualified pure-Python wheel profile has no setup hooks, entrypoints,
// dependencies, extension modules or arbitrary installation destinations.
func wheelMembers(data []byte) (map[string][]byte, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("invalid platform wheel")
	}
	allowed := map[string]bool{}
	for _, name := range platformModules {
		allowed["sonic_platform/"+name] = true
	}
	for _, name := range []string{"METADATA", "WHEEL", "RECORD", "top_level.txt"} {
		allowed["sonic_platform-1.0.dist-info/"+name] = true
	}
	out := map[string][]byte{}
	total := 0
	for _, f := range z.File {
		if !allowed[f.Name] || out[f.Name] != nil || !f.Mode().IsRegular() || f.UncompressedSize64 > 1<<20 {
			return nil, fmt.Errorf("unapproved platform wheel member")
		}
		r, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("unreadable wheel member")
		}
		b, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
		r.Close()
		if err != nil || len(b) > 1<<20 {
			return nil, fmt.Errorf("invalid wheel member")
		}
		total += len(b)
		if total > 16<<20 {
			return nil, fmt.Errorf("expanded wheel too large")
		}
		out[f.Name] = b
	}
	if len(out) != len(allowed) {
		return nil, fmt.Errorf("incomplete platform wheel")
	}
	rows, err := csv.NewReader(bytes.NewReader(out["sonic_platform-1.0.dist-info/RECORD"])).ReadAll()
	if err != nil || len(rows) != len(out) {
		return nil, fmt.Errorf("invalid wheel RECORD")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) != 3 || !allowed[row[0]] || seen[row[0]] {
			return nil, fmt.Errorf("unapproved wheel RECORD destination")
		}
		seen[row[0]] = true
		if row[0] == "sonic_platform-1.0.dist-info/RECORD" {
			if row[1] != "" || row[2] != "" {
				return nil, fmt.Errorf("invalid self RECORD")
			}
			continue
		}
		data := out[row[0]]
		sum := sha256.Sum256(data)
		if row[1] != "sha256="+base64.RawURLEncoding.EncodeToString(sum[:]) || row[2] != strconv.Itoa(len(data)) {
			return nil, fmt.Errorf("wheel RECORD content verification failed")
		}
	}
	metadata := string(out["sonic_platform-1.0.dist-info/METADATA"])
	wheel := string(out["sonic_platform-1.0.dist-info/WHEEL"])
	if !strings.Contains(metadata, "Name: sonic-platform\n") || !strings.Contains(metadata, "Version: 1.0\n") || strings.Contains(strings.ToLower(metadata), "requires-dist:") || !strings.Contains(wheel, "Root-Is-Purelib: true\n") || !strings.Contains(wheel, "Tag: py3-none-any\n") {
		return nil, fmt.Errorf("unsupported wheel distribution metadata")
	}
	return out, nil
}
func validatePlatformWheel(files []File) error {
	bySlot := map[string]File{}
	for _, f := range files {
		bySlot[f.Slot] = f
	}
	wheel, hasWheel := bySlot["PlatformWheel"]
	needsWheel := hasWheel
	for slot := range platformModules {
		_, ok := bySlot[slot]
		needsWheel = needsWheel || ok
	}
	if !needsWheel {
		return nil
	}
	if !hasWheel {
		return fmt.Errorf("platform modules require their immutable generating wheel")
	}
	members, err := wheelMembers(wheel.Data)
	if err != nil {
		return err
	}
	for slot, name := range platformModules {
		f, ok := bySlot[slot]
		if !ok || !bytes.Equal(f.Data, members["sonic_platform/"+name]) {
			return fmt.Errorf("declared host module differs from generating wheel")
		}
	}
	return nil
}
func wheelHashBase64(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (n *Native) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, release := n.Engine.boundContext(ctx)
	defer release()
	if n.Run != nil {
		return n.Run(ctx, name, args...)
	}
	return nativeCommandContext(ctx, name, args...)
}
func (n *Native) activatePlatform(j *journal) error {
	ctx, cancel := n.activationContext(j)
	defer cancel()
	return n.activatePlatformContext(ctx, j)
}
func (n *Native) activationContext(j *journal) (context.Context, context.CancelFunc) {
	budget := 90 * time.Second
	if j.Phase != "RollingBack" && j.Phase != "RecoveringBoot" && !j.Deadline.IsZero() {
		remaining := time.Until(j.Deadline)
		if n.Engine.Uptime != nil {
			remaining = time.Duration(j.DeadlineUptime) - n.Engine.Uptime()
		}
		if remaining < budget {
			budget = remaining
		}
	}
	return context.WithTimeout(context.Background(), budget)
}
func (n *Native) activatePlatformContext(ctx context.Context, j *journal) error {
	if !platformMutation(j) {
		return nil
	}
	hasPlatform := false
	var wheel *savedFile
	for i := range j.Files {
		f := &j.Files[i]
		p, _, err := Destination(f.Slot)
		if err == nil && p == "" {
			hasPlatform = true
		}
		if f.Slot == "PlatformWheel" {
			wheel = f
		}
	}
	if !hasPlatform {
		return nil
	}
	if j.Phase != "RollingBack" {
		if err := n.consumersReady(ctx, false); err != nil {
			return err
		}
		if err := n.consumerBaseline(ctx); err != nil {
			return err
		}
	}
	if wheel != nil {
		if "/"+wheel.Path != coreWheel {
			return fmt.Errorf("unqualified wheel destination")
		}
		if j.Phase != "RollingBack" {
			if err := n.applyPackages(ctx, j, false); err != nil {
				return errors.Join(ErrPackageRepair, err)
			}
			for i, f := range j.Files {
				if f.Slot == "PlatformWheel" {
					data, _, err := n.Engine.read(n.Engine.storage(j, "new", i))
					if err != nil || Digest(data) != f.Hash {
						return fmt.Errorf("candidate wheel lost")
					}
					if err := n.Engine.atomic(f.Path, data, f.Mode); err != nil {
						return err
					}
				}
			}
		}
	}
	if wheel != nil {
		if err := n.configureLaunchers(ctx, j, j.Phase == "RollingBack"); err != nil {
			return err
		}
	} else if _, err := n.command(ctx, "/usr/bin/systemctl", "restart", "pmon.service"); err != nil {
		return err
	}
	if asicMutation(j) {
		if _, err := n.command(ctx, "/usr/bin/systemctl", "restart", "swss.service", "syncd.service"); err != nil {
			return err
		}
	}
	return nil
}
