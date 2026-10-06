// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	errors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"

	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

const (
	RedisDialTimeout     = 30 * time.Second
	RedisReadTimeout     = 5 * time.Second
	RedisWriteTimeout    = 5 * time.Second
	RedisPoolTimeout     = 10 * time.Second
	RedisMaxRetries      = 10
	RedisMinRetryBackoff = 500 * time.Millisecond
	RedisMaxRetryBackoff = 10 * time.Second
	RedisDefaultTimeout  = 5 * time.Second
)

type SonicAgent struct {
	redisAddr   string
	clientPool  map[string]*redis.Client
	poolMutex   sync.RWMutex
	linkByName  func(string) (netlink.Link, error)
	saveConfig  func(context.Context) *agent.Status
	versionInfo func() (map[string]string, error)
	configMutex sync.Mutex
	configDirty bool                 // A failed write/save may leave Redis and persisted config inconsistent.
	journalDir  string               // Explicit persistent root-only VLAN authority journal.
	journalSync func(*os.File) error // Optional directory fsync implementation.

	readSavedPortConfig func() ([]byte, error) // Optional local saved-file reader for tests.

	verifyVLANRuntime func(context.Context, uint32, vlanChangeDB) error // Optional single APPL_DB observation, for tests.

	breakoutJournalDir     string
	resolveBreakout        func(context.Context, string, map[string]string) (*breakoutPlatform, error)
	runBreakout            func(context.Context, *exec.Cmd) ([]byte, error)
	validateBreakoutConfig func(context.Context) error
	breakoutSnapshot       func(context.Context) (vlanChangeDB, string, error)
	breakoutCAS            func(context.Context, string, vlanChangeDB, vlanChangeDB) (bool, error)
	verifyBreakoutRuntime  func(context.Context, *breakoutPlatform, vlanChangeDB) error

	networkJournalDir string
	planNetwork       func(vlanChangeDB, *agent.NetworkRequest) (*networkPlan, error)
}

func getRedisDBIDByName(name string) int {
	switch name {
	case "APPL_DB":
		return 0
	case "ASIC_DB":
		return 1
	case "COUNTERS_DB":
		return 2
	case "LOGLEVEL_DB":
		return 3
	case "CONFIG_DB":
		return 4
	case "PFC_WD_DB":
		return 5
	case "FLEX_COUNTER_DB":
		return 5
	case "STATE_DB":
		return 6
	case "SNMP_OVERLAY_DB":
		return 7
	case "RESTagent_DB":
		return 8
	case "GB_ASIC_DB":
		return 9
	case "GB_COUNTERS_DB":
		return 10
	case "GB_FLEX_COUNTER_DB":
		return 11
	case "APPL_STATE_DB":
		return 14
	default:
		return -1
	}
}

func NewSonicRedisAgent(redisAddr string) (*SonicAgent, error) {
	// Test connection first
	testClient := redis.NewClient(&redis.Options{
		Addr:             redisAddr,
		DB:               4, // Test with CONFIG_DB
		DialTimeout:      RedisDialTimeout,
		ReadTimeout:      RedisReadTimeout,
		WriteTimeout:     RedisWriteTimeout,
		PoolTimeout:      RedisPoolTimeout,
		MaxRetries:       RedisMaxRetries,
		MinRetryBackoff:  RedisMinRetryBackoff,
		MaxRetryBackoff:  RedisMaxRetryBackoff,
		DisableIndentity: true, // Disable identity/protocol checks to avoid warnings
	})

	if err := testClient.Ping(context.Background()).Err(); err != nil {
		if err := testClient.Close(); err != nil {
			return nil, fmt.Errorf("failed to close Redis client: %w", err)
		}
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	if err := testClient.Close(); err != nil {
		return nil, fmt.Errorf("failed to close Redis client: %w", err)
	}

	return &SonicAgent{
		redisAddr:  redisAddr,
		clientPool: make(map[string]*redis.Client),
		poolMutex:  sync.RWMutex{},
	}, nil
}

func (m *SonicAgent) Connect(dbName string) (*redis.Client, error) {
	m.poolMutex.RLock()
	if client, exists := m.clientPool[dbName]; exists {
		m.poolMutex.RUnlock()

		// Test if connection is still alive
		if err := client.Ping(context.Background()).Err(); err == nil {
			return client, nil
		}
	} else {
		m.poolMutex.RUnlock()
	}

	// Need to create new client (write lock)
	m.poolMutex.Lock()
	defer m.poolMutex.Unlock()

	// Double-check in case another goroutine created it
	if client, exists := m.clientPool[dbName]; exists {
		if err := client.Ping(context.Background()).Err(); err == nil {
			return client, nil
		}
		// Close the dead connection
		if err := client.Close(); err != nil {
			return nil, fmt.Errorf("failed to close Redis client: %w", err)
		}
		delete(m.clientPool, dbName)
	}

	// Create new client
	dbID := getRedisDBIDByName(dbName)
	if dbID == -1 {
		return nil, fmt.Errorf("unknown database name: %s", dbName)
	}

	client := redis.NewClient(&redis.Options{
		Addr:                  m.redisAddr,
		DB:                    dbID,
		DialTimeout:           RedisDialTimeout,
		ReadTimeout:           RedisReadTimeout,
		WriteTimeout:          RedisWriteTimeout,
		PoolTimeout:           RedisPoolTimeout,
		MaxRetries:            RedisMaxRetries,
		ContextTimeoutEnabled: true,

		// Connection pool settings
		PoolSize:     10, // Maximum number of socket connections
		MinIdleConns: 2,  // Minimum idle connections
		MaxIdleConns: 5,  // Maximum idle connections

		// Connection lifecycle
		ConnMaxIdleTime: 30 * time.Minute,
		ConnMaxLifetime: 1 * time.Hour,

		DisableIndentity: true, // Disable identity/protocol checks to avoid warnings
	})

	// Test the new connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		if err := client.Close(); err != nil {
			return nil, fmt.Errorf("failed to close Redis client: %w", err)
		}
		return nil, fmt.Errorf("failed to connect to Redis database %s: %w", dbName, err)
	}

	m.clientPool[dbName] = client

	return client, nil
}

func (m *SonicAgent) GetDeviceInfo(ctx context.Context) (*agent.SwitchDevice, *agent.Status) {
	rdb, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to Redis: %v", err))
	}

	const deviceKey = "DEVICE_METADATA|localhost"
	fields, err := rdb.HGetAll(ctx, deviceKey).Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to get device info: %v", err))
	}

	mac, ok := fields["mac"]
	if !ok {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, "missing or invalid MAC address")
	}

	hwsku := fields["hwsku"]
	sonicOSVersion := fields["sonic_os_version"]
	asicType := fields["asic_type"]

	// If values are missing from Redis, try to get from sonic_version.yml
	if hwsku == "" || sonicOSVersion == "" || asicType == "" {
		readVersion := m.versionInfo
		if readVersion == nil {
			readVersion = GetSonicVersionInfo
		}
		if versionInfo, err := readVersion(); err == nil {
			if hwsku == "" {
				hwsku = versionInfo["hwsku"]
			}
			if sonicOSVersion == "" {
				sonicOSVersion = versionInfo["sonic_os_version"]
				if sonicOSVersion == "" {
					sonicOSVersion = versionInfo["build_version"]
				}
			}
			if asicType == "" {
				asicType = versionInfo["asic_type"]
			}
		}
	}

	return &agent.SwitchDevice{
		TypeMeta: agent.TypeMeta{
			Kind: agent.DeviceKind,
		},
		LocalMacAddress: mac,
		Hwsku:           hwsku,
		SonicOSVersion:  sonicOSVersion,
		AsicType:        asicType,
		Readiness:       uint32(agent.StatusReady),
	}, nil
}

func (m *SonicAgent) ListInterfaces(ctx context.Context) (*agent.InterfaceList, *agent.Status) {
	configDB, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to CONFIG_DB: %v", err))
	}

	applDB, err := m.Connect("APPL_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to APPL_DB: %v", err))
	}

	pattern := "PORT|*"
	keys, err := configDB.Keys(ctx, pattern).Result()

	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to obtain iface keys: %v", err))
	}

	interfaces := make([]agent.Interface, 0, len(keys))
	for _, key := range keys {
		var name string
		if _, err := fmt.Sscanf(key, "PORT|%s", &name); err != nil {
			return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to parse interface name from key %s: %v", key, err))
		}

		configFields, err := configDB.HGetAll(ctx, key).Result()
		if err != nil {
			return nil, errors.NewErrorStatus(errors.REDIS_KEY_CHECK_FAIL, fmt.Sprintf("failed to get config for interface %s: %v", name, err))
		}
		applKey := fmt.Sprintf("PORT_TABLE:%s", name)
		applFields, err := applDB.HGetAll(ctx, applKey).Result()
		if err != nil {
			return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to get state info for interface %s: %v", name, err))
		}

		operStatus := parseDeviceStatus(applFields["oper_status"])
		adminStatus := parseDeviceStatus(configFields["admin_status"])

		// Use device MAC as interface MAC (common in SONiC)
		link, err := m.getLinkByName(name)
		if err != nil {
			return nil, agent.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("failed to get interface %s: %v", name, err))
		}

		mac := link.Attrs().HardwareAddr
		if mac == nil {
			return nil, agent.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("no MAC address found for interface %s", name))
		}

		abstractName, err := agent.NativeNameToAbstractName(name)
		if err != nil {
			return nil, agent.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to convert native name to abstract name: %v", err))
		}

		iface := agent.Interface{
			TypeMeta: agent.TypeMeta{
				Kind: agent.InterfaceKind,
			},
			Name:            abstractName,
			NativeName:      name,
			AliasName:       configFields["alias"],
			MacAddress:      mac.String(),
			OperationStatus: operStatus,
			AdminStatus:     adminStatus,
		}
		interfaces = append(interfaces, iface)
	}

	return &agent.InterfaceList{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceListKind,
		},
		Items:  interfaces,
		Status: agent.Status{Code: 0, Message: "ok"},
	}, nil
}

func (m *SonicAgent) SaveConfig(ctx context.Context) *agent.Status {
	unlock, status := m.lockOrdinaryConfig(ctx, 0)
	if status != nil {
		return status
	}
	defer unlock()
	m.configDirty = true
	if status := m.saveConfigLocked(ctx); status != nil && status.Code != 0 {
		return status
	}
	m.configDirty = false
	return nil
}

// saveConfigLocked is for callers already holding configMutex and, when
// configured, the journal lock. Authority recovery intentionally bypasses the
// ordinary pending guard while persisting its own recorded operation.
func (m *SonicAgent) saveConfigLocked(ctx context.Context) *agent.Status {
	if err := ctx.Err(); err != nil {
		return errors.NewErrorStatus(errors.SERVER_ERROR, err.Error())
	}
	if m.saveConfig != nil {
		return m.saveConfig(ctx)
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Printf("Failed to connect to system bus: %v", err)
		return errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to D-Bus: %v", err))
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			log.Printf("Failed to close D-Bus connection: %v", err)
		}
	}()

	obj := conn.Object("org.SONiC.HostService", "/org/SONiC/HostService/config")
	return saveConfigViaDBus(ctx, obj.CallWithContext)
}

func saveConfigViaDBus(ctx context.Context, callWithContext func(context.Context, string, dbus.Flags, ...any) *dbus.Call) *agent.Status {
	call := callWithContext(ctx, "org.SONiC.HostService.config.save", 0, "")
	var exitCode int32
	var output string
	if err := call.Store(&exitCode, &output); err != nil {
		return errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to save config via D-Bus: %v", err))
	}
	// HostService output may contain sensitive config; report only the exit code.
	if exitCode != 0 {
		return errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to save config via D-Bus: exit code %d", exitCode))
	}

	log.Printf("Config saved successfully via D-Bus")
	return nil
}

func (m *SonicAgent) SetInterfaceAdminStatus(ctx context.Context, iface *agent.Interface) (*agent.Interface, *agent.Status) {
	if iface == nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "interface cannot be nil")
	}
	if _, err := agent.ValidateDeviceStatusStr(string(iface.AdminStatus)); err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, err.Error())
	}
	return m.setInterfaceField(ctx, iface, "admin_status", string(iface.AdminStatus))
}

func (m *SonicAgent) GetInterface(ctx context.Context, iface *agent.Interface) (*agent.Interface, *agent.Status) {
	// Validate input
	var ifaceName string
	var err error

	if iface == nil || iface.Name == "" {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "interface name cannot be empty")
	}
	if !strings.HasPrefix(iface.Name, "Ethernet") && !strings.HasPrefix(iface.Name, "eth") {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "invalid interface name. Must start with 'Ethernet' or 'eth'")
	}
	if strings.HasPrefix(iface.Name, "eth") {
		ifaceName, err = agent.AbstractNameToNativeName(iface.Name)
		if err != nil {
			return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to convert abstract name to native name: %v", err))
		}
	} else {
		ifaceName = iface.Name
	}

	configDB, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to CONFIG_DB: %v", err))
	}

	// Check if interface exists in CONFIG_DB
	portKey := fmt.Sprintf("PORT|%s", ifaceName)
	configFields, err := configDB.HGetAll(ctx, portKey).Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to check interface existence: %v", err))
	}
	if len(configFields) == 0 {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("interface %s not found", ifaceName))
	}

	applDB, err := m.Connect("APPL_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to APPL_DB: %v", err))
	}
	applKey := fmt.Sprintf("PORT_TABLE:%s", ifaceName)
	applFields, err := applDB.HGetAll(ctx, applKey).Result()
	if err != nil {
		// If state info is not available, use default values
		applFields = make(map[string]string)
	}

	operStatus := parseDeviceStatus(applFields["oper_status"])
	adminStatus := parseDeviceStatus(configFields["admin_status"])

	// Get interface MAC address using netlink
	link, err := m.getLinkByName(ifaceName)
	if err != nil {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("failed to get interface %s: %v", ifaceName, err))
	}

	mac := link.Attrs().HardwareAddr
	if mac == nil {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("no MAC address found for interface %s", ifaceName))
	}

	abstractName, err := agent.NativeNameToAbstractName(ifaceName)
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to convert native name to abstract name: %v", err))
	}

	resultInterface := &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name:            abstractName,
		NativeName:      ifaceName,
		AliasName:       configFields["alias"],
		MacAddress:      mac.String(),
		OperationStatus: operStatus,
		AdminStatus:     adminStatus,
		Status:          agent.Status{Code: 0, Message: "ok"},
	}

	return resultInterface, nil
}

func (m *SonicAgent) GetInterfaceNeighbor(ctx context.Context, iface *agent.Interface) (*agent.InterfaceNeighbor, *agent.Status) {
	var ifaceName string
	var err error

	if iface == nil || iface.Name == "" {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "interface name cannot be empty")
	}
	if !strings.HasPrefix(iface.Name, "Ethernet") && !strings.HasPrefix(iface.Name, "eth") {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "invalid interface name. Must start with 'Ethernet' or 'eth'")
	}
	if strings.HasPrefix(iface.Name, "eth") {
		ifaceName, err = agent.AbstractNameToNativeName(iface.Name)
		if err != nil {
			return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to convert abstract name to native name: %v", err))
		}
	} else {
		ifaceName = iface.Name
	}

	applDB, err := m.Connect("APPL_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to APPL_DB: %v", err))
	}

	lldpKey := fmt.Sprintf("LLDP_ENTRY_TABLE:%s", ifaceName)

	// Check if LLDP entry exists for this interface
	exists, err := applDB.Exists(ctx, lldpKey).Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to check LLDP entry existence: %v", err))
	}
	if exists == 0 {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("no LLDP neighbor found for interface %s", ifaceName))
	}

	// Get all LLDP fields
	lldpFields, err := applDB.HGetAll(ctx, lldpKey).Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to get LLDP entry: %v", err))
	}

	// MacAddress from lldp_rem_chassis_id (when chassis_id_subtype is 4 - MAC address)
	macAddress := lldpFields["lldp_rem_chassis_id"]

	// SystemName from lldp_rem_sys_name
	systemName := lldpFields["lldp_rem_sys_name"]

	// Handle (remote interface name) from lldp_rem_port_desc
	// Note: lldp_rem_port_id contains "Eth5(Port5)" format, lldp_rem_port_desc contains "Ethernet16"
	handle := lldpFields["lldp_rem_port_desc"]
	if handle == "" {
		// Fallback to lldp_rem_port_id if port_desc is not available
		handle = lldpFields["lldp_rem_port_id"]
	} else if _, valid := ethernetNumber(handle); valid {
		// Remote descriptions are arbitrary text, not necessarily SONiC names.
		if abstract, err := agent.NativeNameToAbstractName(handle); err == nil {
			handle = abstract
		}
	}

	// Validate that we have the essential information
	if macAddress == "" || systemName == "" {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("incomplete LLDP information for interface %s", ifaceName))
	}

	neighbor := &agent.InterfaceNeighbor{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceNeighborKind,
		},
		Name:       ifaceName, // Interface name of yourself
		MacAddress: macAddress,
		SystemName: systemName,
		Handle:     handle, // Remote interface name
		Status:     agent.Status{Code: 0, Message: "ok"},
	}

	return neighbor, nil
}

func (m *SonicAgent) ListPorts(ctx context.Context) (*agent.PortList, *agent.Status) {
	configDB, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to CONFIG_DB: %v", err))
	}
	configKeys, err := configDB.Keys(ctx, "PORT|*").Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to obtain PORT keys: %v", err))
	}
	config := make(map[string]map[string]string, len(configKeys))
	parents := make(map[int]string)
	indexed := make(map[string]bool)
	for _, key := range configKeys {
		name := strings.TrimPrefix(key, "PORT|")
		number, valid := ethernetNumber(name)
		if !valid {
			continue
		}
		fields, err := configDB.HGetAll(ctx, key).Result()
		if err != nil {
			return nil, errors.NewErrorStatus(errors.REDIS_KEY_CHECK_FAIL, fmt.Sprintf("failed to get config for port %s: %v", name, err))
		}
		config[name] = fields
		index, err := strconv.Atoi(fields["index"])
		if err != nil || index < 0 {
			continue // Without a usable physical index, require explicit parent metadata.
		}
		indexed[name] = true
		parent, exists := parents[index]
		parentNumber, _ := ethernetNumber(parent)
		if !exists || number < parentNumber {
			parents[index] = name
		}
	}

	// Connect to APPL_DB (table 0)
	applDB, err := m.Connect("APPL_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to APPL_DB: %v", err))
	}

	// List keys starting with PORT_TABLE
	pattern := "PORT_TABLE:*"
	keys, err := applDB.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to obtain PORT_TABLE keys: %v", err))
	}

	// Breakout members share a CONFIG_DB index. Use the lowest existing native
	// name, not Ethernet(index*4): platforms can number the final cages sparsely.
	portAliases := make(map[string]string)
	for _, parent := range parents {
		portAliases[parent] = config[parent]["alias"]
	}
	for _, key := range keys {
		portName := strings.TrimPrefix(key, "PORT_TABLE:")
		if _, valid := ethernetNumber(portName); !valid {
			continue // Skip malformed keys
		}
		if indexed[portName] {
			continue // CONFIG_DB already selected exactly one parent for this index.
		}

		// Get the port configuration
		fields, err := applDB.HGetAll(ctx, key).Result()
		if err != nil {
			continue // Skip if we can't get the fields
		}

		// Check if this represents a physical port by examining the "parent_port" field
		// If parent_port equals the port name itself, it's a physical port
		parentPort, exists := fields["parent_port"]
		if !exists || parentPort != portName {
			continue // Skip non-physical ports (sub-interfaces, VLANs, etc.)
		}

		alias, configured := config[portName]["alias"]
		if !configured {
			alias = fields["alias"]
		}
		portAliases[portName] = alias
	}
	names := make([]string, 0, len(portAliases))
	for name := range portAliases {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		a, _ := ethernetNumber(names[i])
		b, _ := ethernetNumber(names[j])
		return a < b
	})
	ports := make([]agent.Port, 0, len(names))
	for _, portName := range names {
		alias := portAliases[portName]
		if alias == "" {
			alias = portName
		}
		port := agent.Port{
			TypeMeta: agent.TypeMeta{
				Kind: agent.PortKind,
			},
			Name:   portName,
			Alias:  alias,
			Status: agent.Status{Code: 0, Message: "ok"},
		}
		ports = append(ports, port)
	}

	return &agent.PortList{
		TypeMeta: agent.TypeMeta{
			Kind: agent.PortListKind,
		},
		Items:  ports,
		Status: agent.Status{Code: 0, Message: "ok"},
	}, nil
}

func (m *SonicAgent) SetInterfaceAliasName(ctx context.Context, iface *agent.Interface) (*agent.Interface, *agent.Status) {
	if iface == nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "interface cannot be nil")
	}
	return m.setInterfaceField(ctx, iface, "alias", iface.AliasName)
}

// Both setters validate against the same CONFIG_DB snapshot and write only a
// changed field. Admin persistence is also independently checked on no-op calls.
// In particular, an admin update never writes an alias.
func (m *SonicAgent) setInterfaceField(ctx context.Context, iface *agent.Interface, field, desired string) (*agent.Interface, *agent.Status) {
	var ifaceName string
	var err error

	if iface == nil || iface.Name == "" {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "interface name cannot be empty")
	}
	if !strings.HasPrefix(iface.Name, "Ethernet") && !strings.HasPrefix(iface.Name, "eth") {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "invalid interface name. Must start with 'Ethernet' or 'eth'")
	}
	if strings.HasPrefix(iface.Name, "eth") {
		ifaceName, err = agent.AbstractNameToNativeName(iface.Name)
		if err != nil {
			return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to convert abstract name to native name: %v", err))
		}
	} else {
		ifaceName = iface.Name
	}
	if _, valid := ethernetNumber(ifaceName); !valid {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "invalid native interface name")
	}
	abstractName, err := agent.NativeNameToAbstractName(ifaceName)
	if err != nil || (strings.HasPrefix(iface.Name, "eth") && abstractName != iface.Name) {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "invalid abstract interface name")
	}
	if iface.NativeName != "" && iface.NativeName != ifaceName {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, "interface native identity mismatch")
	}
	// SaveConfig persists the whole DB, so serialize setters and retain uncertain
	// persistence across requests rather than treating matching Redis values as saved.
	unlock, status := m.lockOrdinaryConfig(ctx, 0)
	if status != nil {
		return nil, status
	}
	defer unlock()

	configDB, err := m.Connect("CONFIG_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to CONFIG_DB: %v", err))
	}

	portKey := fmt.Sprintf("PORT|%s", ifaceName)
	fields, err := configDB.HGetAll(ctx, portKey).Result()
	if err != nil {
		return nil, errors.NewErrorStatus(errors.REDIS_KEY_CHECK_FAIL, fmt.Sprintf("failed to get current interface config: %v", err))
	}
	if len(fields) == 0 {
		return nil, errors.NewErrorStatus(errors.NOT_FOUND, fmt.Sprintf("interface %s not found", ifaceName))
	}
	current, existed := fields[field]
	changed := current != desired
	if changed {
		m.configDirty = true
		err = configDB.HSet(ctx, portKey, field, desired).Err()
		if err != nil {
			return nil, errors.NewErrorStatus(errors.REDIS_HSET_FAIL, fmt.Sprintf("failed to set %s: %v", field, err))
		}
	}
	if field == "admin_status" && !m.adminPersisted(ifaceName, desired) {
		m.configDirty = true
	}
	if m.configDirty {
		if status := m.saveConfigLocked(ctx); status != nil && status.Code != 0 {
			if changed {
				// Request cancellation must not prevent restoring the pre-write value.
				rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RedisDefaultTimeout)
				if existed {
					err = configDB.HSet(rollbackCtx, portKey, field, current).Err()
				} else {
					err = configDB.HDel(rollbackCtx, portKey, field).Err()
				}
				cancel()
				if err != nil {
					return nil, errors.NewErrorStatus(errors.REDIS_HSET_FAIL, fmt.Sprintf("%s; failed to rollback %s: %v", status.Message, field, err))
				}
			}
			return nil, status
		}
		m.configDirty = false
	}
	if changed {
		fields[field] = desired
	}
	if field == "admin_status" {
		// A matching Redis value after a restart cannot hide an interrupted save.
		// Also reject concurrent target changes rather than returning our old read.
		persisted := m.adminPersisted(ifaceName, desired)
		latest, err := configDB.HGetAll(ctx, portKey).Result()
		if err != nil || !reflect.DeepEqual(latest, fields) || !persisted {
			m.configDirty = true
			return nil, errors.NewErrorStatus(errors.SERVER_ERROR, "admin state live/saved verification failed; retry persistence")
		}
	}

	applDB, err := m.Connect("APPL_DB")
	if err != nil {
		return nil, errors.NewErrorStatus(errors.BAD_REQUEST, fmt.Sprintf("failed to connect to APPL_DB: %v", err))
	}
	applKey := fmt.Sprintf("PORT_TABLE:%s", ifaceName)
	applFields, err := applDB.HGetAll(ctx, applKey).Result()
	if err != nil {
		// If state info is not available, use default values
		applFields = make(map[string]string)
	}

	return &agent.Interface{
		TypeMeta:                 agent.TypeMeta{Kind: agent.InterfaceKind},
		Name:                     abstractName,
		NativeName:               ifaceName,
		AliasName:                fields["alias"],
		AdminStatus:              parseDeviceStatus(fields["admin_status"]),
		OperationStatus:          parseDeviceStatus(applFields["oper_status"]),
		AdminPersistenceVerified: field == "admin_status",
		Status:                   agent.Status{Code: 0, Message: "ok"},
	}, nil
}
