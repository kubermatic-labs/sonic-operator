// SPDX-License-Identifier: Apache-2.0
// Package artifact implements the bounded site artifact lifecycle shared by the
// controller, mTLS agent facade and independent recovery supervisor.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"regexp"
)

const MaxBundleBytes = 128 << 20

var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type AgentOptions struct {
	HostConfig    bool   `json:"hostConfig,omitempty"`
	HostGuard     bool   `json:"hostGuard,omitempty"`
	BindAddress   string `json:"bindAddress"`
	Port          int    `json:"port"`
	ReadOnly      bool   `json:"readOnly,omitempty"`
	VLANAuthority bool   `json:"vlanAuthority,omitempty"`
	Breakout      bool   `json:"breakout,omitempty"`
	Network       bool   `json:"network,omitempty"`
	FRRMigration  bool   `json:"frrMigration,omitempty"`
	TrafficPolicy bool   `json:"trafficPolicy,omitempty"`
	Redundancy    bool   `json:"redundancy,omitempty"`
	Artifacts     bool   `json:"artifacts,omitempty"`
}
type File struct {
	Slot   string `json:"slot"`
	SHA256 string `json:"sha256"`
	// Data is transport-only. Never serialize a Bundle into an ownership journal.
	Data []byte `json:"data,omitempty"`
}
type Bundle struct {
	Bootstrap        *Bootstrap    `json:"bootstrap,omitempty"`
	RetireLegacyHook bool          `json:"retireLegacyHook,omitempty"`
	Activation       string        `json:"activation,omitempty"`
	Owner            string        `json:"owner"`
	Target           string        `json:"target"`
	Generation       int64         `json:"generation"`
	Baseline         string        `json:"baseline"`
	Files            []File        `json:"files"`
	Agent            *AgentOptions `json:"agent,omitempty"`
}
type Request struct {
	ContentSession string `json:"contentSession,omitempty"`
	Operation      string `json:"operation"`
	Bundle         Bundle `json:"bundle"`
	Token          string `json:"token,omitempty"`
}
type Result struct {
	Reason        string `json:"reason,omitempty"`
	Configuration bool   `json:"configuration"`
	Runtime       bool   `json:"runtime"`
	Persistence   bool   `json:"persistence"`
	Phase         string `json:"phase"`
	Token         string `json:"token,omitempty"`
	Identity      string `json:"identity,omitempty"`
}

func Digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func (b Bundle) Identity() string {
	b = b.WithoutContent()
	data, _ := json.Marshal(b)
	return Digest(data)
}

// Empty paths denote platform slots requiring a locally approved baseline map.
// The RPC cannot supply filesystem paths or invent new platform module names.
func Destination(slot string) (string, fs.FileMode, error) {
	switch slot {
	case "AgentBinary":
		return "/usr/local/sbin/sonic-operator-agent", 0755, nil
	case "AgentCertificate":
		return "/etc/sonic-operator-agent/tls.crt", 0600, nil
	case "AgentKey":
		return "/etc/sonic-operator-agent/tls.key", 0600, nil
	case "AgentCA":
		return "/etc/sonic-operator-agent/ca.crt", 0600, nil
	case "PlatformJSON", "HWSKUJSON", "PortConfig", "SAIProfile", "BroadcomConfig", "PlatformWheel", "PlatformInit", "PlatformChassis", "PlatformSFP", "PlatformEEPROM", "PlatformPSU", "PlatformFan", "PlatformThermal", "PlatformAPI", "PlatformComponent", "PlatformFanDrawer":
		return "", 0644, nil
	default:
		return "", 0, fmt.Errorf("unsupported artifact slot")
	}
}
func SecretSlot(slot string) bool {
	return slot == "AgentKey" || slot == "AgentCertificate" || slot == "AgentCA"
}
func (b Bundle) Validate(content bool) error {
	if b.Agent != nil && b.Agent.HostConfig && (b.Bootstrap == nil || b.Bootstrap.HostRecovery == nil || !b.Agent.HostGuard) {
		return fmt.Errorf("HostConfig requires immutable host recovery and HostGuard")
	}
	if b.Bootstrap != nil && b.Bootstrap.HostRecovery != nil && (b.Agent == nil || !b.Agent.HostGuard) {
		return fmt.Errorf("host baseline requires retained HostGuard")
	}
	if b.Bootstrap != nil {
		if err := b.Bootstrap.Validate(content && (len(b.Bootstrap.Supervisor) > 0 || len(b.Bootstrap.Policy) > 0)); err != nil {
			return err
		}
	}
	if b.Activation != "" && b.Activation != "AgentRestart" && b.Activation != "PlatformNextBoot" {
		return fmt.Errorf("unsupported artifact activation")
	}
	if b.Owner == "" || len(b.Owner) > 256 || b.Target == "" || len(b.Target) > 1024 || b.Generation < 1 || b.Baseline == "" || len(b.Baseline) > 256 {
		return fmt.Errorf("artifact ownership and baseline required")
	}
	if len(b.Files) == 0 || len(b.Files) > 64 {
		return fmt.Errorf("artifact file count out of bounds")
	}
	seen := map[string]bool{}
	size := 0
	if b.Bootstrap != nil {
		size = len(b.Bootstrap.Supervisor) + len(b.Bootstrap.Policy)
		_ = b.Bootstrap.HostRecovery.payloads(func(_ string, p *[]byte, _ uint64) error { size += len(*p); return nil })
	}
	for _, f := range b.Files {
		if _, _, err := Destination(f.Slot); err != nil {
			return err
		}
		if seen[f.Slot] || !shaPattern.MatchString(f.SHA256) {
			return fmt.Errorf("invalid or duplicate artifact identity")
		}
		seen[f.Slot] = true
		size += len(f.Data)
		if content && (len(f.Data) == 0 || Digest(f.Data) != f.SHA256) {
			return fmt.Errorf("artifact content verification failed")
		}
	}
	if size > MaxBundleBytes {
		return fmt.Errorf("artifact bundle too large")
	}
	if b.Agent != nil {
		if _, err := AgentUnit(*b.Agent); err != nil {
			return err
		}
	}
	return nil
}
func AgentUnit(o AgentOptions) ([]byte, error) {
	ip, err := netip.ParseAddr(o.BindAddress)
	if err != nil || ip.Zone() != "" || o.Port < 1 || o.Port > 65535 || (!o.Network && (o.FRRMigration || o.TrafficPolicy || o.Redundancy)) {
		return nil, fmt.Errorf("invalid typed agent options")
	}
	host := ""
	if o.HostConfig || o.HostGuard {
		host = fmt.Sprintf(" --allow-host-config=%t --host-journal-dir=/host/sonic-operator-host-journal", o.HostConfig)
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=SONiC operator agent
After=network.target sonic-operator-artifact-supervisor.service
[Service]
Type=simple
User=root
Group=root
UMask=0077
RuntimeDirectory=sonic-operator-agent
RuntimeDirectoryMode=0700
Environment=GOMEMLIMIT=384MiB
MemoryHigh=512M
MemoryMax=768M
ExecStart=/usr/local/sbin/sonic-operator-agent --bind-address=%s --port=%d --read-only=%t --tls-cert-file=/etc/sonic-operator-agent/tls.crt --tls-key-file=/etc/sonic-operator-agent/tls.key --tls-client-ca-file=/etc/sonic-operator-agent/ca.crt --allow-authoritative-vlans=%t --vlan-authority-journal-dir=/host/sonic-operator-vlan-journal --allow-breakout=%t --breakout-journal-dir=/host/sonic-operator-breakout-journal --allow-network-config=%t --network-journal-dir=/host/sonic-operator-network-journal --allow-frr-migration=%t --allow-traffic-policy=%t --allow-redundancy=%t --allow-artifacts=%t --artifact-reservation-v1=true%s
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
`, o.BindAddress, o.Port, o.ReadOnly, o.VLANAuthority, o.Breakout, o.Network, o.FRRMigration, o.TrafficPolicy, o.Redundancy, o.Artifacts, host)), nil
}
