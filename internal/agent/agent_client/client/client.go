// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	hp "github.com/ironcore-dev/sonic-operator/internal/agent/hostproto"
	"github.com/ironcore-dev/sonic-operator/internal/agent/transport"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
)

type SwitchAgentClient interface {
	GetDeviceInfo(ctx context.Context) (*agent.SwitchDevice, error)
	ListInterfaces(ctx context.Context) (*agent.InterfaceList, error)
	GetInterfaceByAbstractName(ctx context.Context, iface *agent.Interface) (*agent.Interface, error)

	GetInterfaceNeighbor(ctx context.Context, iface *agent.Interface) (*agent.InterfaceNeighbor, error)

	SetInterfaceAdminStatus(ctx context.Context, iface *agent.Interface) (*agent.Interface, error)
	SetInterfaceAliasName(ctx context.Context, iface *agent.Interface) (*agent.Interface, error)

	ListPorts(ctx context.Context) (*agent.PortList, error)

	SaveConfig(ctx context.Context) error
}

type defaultSwitchAgentClient struct {
	Address        string
	ConnectTimeout time.Duration

	conn   *grpc.ClientConn
	client pb.SwitchAgentServiceClient
}

func NewDefaultSwitchAgentClient(address string, connectTimeout time.Duration) (SwitchAgentClient, error) {
	if address == "" {
		address = "localhost:50051"
	}

	if connectTimeout == 0 {
		connectTimeout = 4 * time.Second
	}

	if connectTimeout < 0 {
		return nil, fmt.Errorf("connect timeout must not be negative")
	}

	tlsConfig, err := transport.LoadTLSConfig(
		os.Getenv("SONIC_AGENT_TLS_CERT_FILE"),
		os.Getenv("SONIC_AGENT_TLS_KEY_FILE"),
		os.Getenv("SONIC_AGENT_TLS_CA_FILE"),
	)
	if err != nil {
		return nil, fmt.Errorf("configure agent client TLS (SONIC_AGENT_TLS_CERT_FILE, SONIC_AGENT_TLS_KEY_FILE, SONIC_AGENT_TLS_CA_FILE): %w", err)
	}
	tlsConfig.ServerName = os.Getenv("SONIC_AGENT_TLS_SERVER_NAME")
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		// Bound calls even when callers supply no deadline; shorter caller deadlines win.
		grpc.WithUnaryInterceptor(rpcTimeoutInterceptor(connectTimeout)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to switch proxy: %w", err)
	}

	return &defaultSwitchAgentClient{
		Address:        address,
		ConnectTimeout: connectTimeout,
		conn:           conn,
		client:         pb.NewSwitchAgentServiceClient(conn),
	}, nil
}

func rpcTimeoutInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		callTimeout := timeout
		if method == hp.HostService_Ensure_FullMethodName {
			callTimeout = 90 * time.Second
		}
		if method == hp.HostService_Get_FullMethodName || method == hp.HostService_Confirm_FullMethodName {
			callTimeout = 15 * time.Second
		}
		if method == pb.ArtifactService_Stage_FullMethodName || method == pb.ArtifactService_Bootstrap_FullMethodName || method == pb.ArtifactService_PrepareContent_FullMethodName {
			callTimeout = 90 * time.Second
		}
		if method == pb.ArtifactService_Observe_FullMethodName || method == pb.ArtifactService_Confirm_FullMethodName {
			callTimeout = 75 * time.Second
		}
		if method == pb.SwitchAgentService_ReconcilePortBreakout_FullMethodName {
			callTimeout = 180 * time.Second
		}
		if method == pb.SwitchAgentService_EnsureNetworkResource_FullMethodName || method == pb.SwitchAgentService_RecoverNetworkResource_FullMethodName {
			callTimeout = 120 * time.Second
		}
		if method == pb.SwitchAgentService_GetNetworkResource_FullMethodName {
			callTimeout = 15 * time.Second
		}
		ctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// Close releases the reusable connection. It is optional on SwitchAgentClient so
// existing fake clients do not need to implement connection lifecycle management.
func (c *defaultSwitchAgentClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func responseError(method string, status *pb.Status) error {
	if status == nil {
		return fmt.Errorf("%s: missing status in agent response", method)
	}
	if status.GetCode() != 0 {
		return fmt.Errorf("%s: agent status %d: %s", method, status.GetCode(), status.GetMessage())
	}
	return nil
}

func (c *defaultSwitchAgentClient) GetDeviceInfo(ctx context.Context) (*agent.SwitchDevice, error) {
	resp, err := c.client.GetDeviceInfo(ctx, &pb.GetDeviceInfoRequest{})
	if err != nil {
		return nil, err
	}
	if err := responseError("GetDeviceInfo", resp.GetStatus()); err != nil {
		return nil, err
	}

	device := &agent.SwitchDevice{
		TypeMeta: agent.TypeMeta{
			Kind: agent.DeviceKind,
		},
		LocalMacAddress: resp.GetLocalMacAddress(),
		Hwsku:           resp.GetHwsku(),
		SonicOSVersion:  resp.GetSonicOsVersion(),
		AsicType:        resp.GetAsicType(),
		Readiness:       resp.GetReadiness(),
		Status:          agent.ProtoStatusToStatus(resp.GetStatus()),
	}

	return device, nil
}

func (c *defaultSwitchAgentClient) ListInterfaces(ctx context.Context) (*agent.InterfaceList, error) {
	resp, err := c.client.ListInterfaces(ctx, &pb.ListInterfacesRequest{})
	if err != nil {
		return nil, err
	}
	if err := responseError("ListInterfaces", resp.GetStatus()); err != nil {
		return nil, err
	}

	interfaces := make([]agent.Interface, len(resp.GetInterfaces()))
	for i, iface := range resp.GetInterfaces() {
		interfaces[i] = agent.Interface{
			TypeMeta: agent.TypeMeta{
				Kind: agent.InterfaceKind,
			},
			Name:            iface.GetName(),
			NativeName:      iface.GetNativeName(),
			AliasName:       iface.GetAliasName(),
			MacAddress:      iface.GetMacAddress(),
			OperationStatus: agent.DeviceStatus(iface.GetOperationalStatus()),
			AdminStatus:     agent.DeviceStatus(iface.GetAdminStatus()),
		}
	}

	interfaceList := &agent.InterfaceList{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceListKind,
		},
		Items:  interfaces,
		Status: agent.ProtoStatusToStatus(resp.GetStatus()),
	}

	return interfaceList, nil
}

func (c *defaultSwitchAgentClient) SetInterfaceAdminStatus(ctx context.Context, iface *agent.Interface) (*agent.Interface, error) {
	resp, err := c.client.SetInterfaceAdminStatus(ctx, &pb.SetInterfaceAdminStatusRequest{
		InterfaceName: iface.GetName(),
		AdminStatus:   string(iface.AdminStatus),
	})
	if err != nil {
		fmt.Println("Error occurred while setting interface admin status:", err)
		return nil, err
	}

	if resp.GetStatus().Code != 0 {
		fmt.Println("Error occurred while setting interface admin status:", resp.GetStatus().GetMessage())
		return &agent.Interface{
			Status: agent.ProtoStatusToStatus(resp.GetStatus()),
		}, fmt.Errorf("failed to set interface admin status: %s", resp.GetStatus().GetMessage())
	}
	iface.Name = resp.GetInterface().GetName()
	iface.AliasName = resp.GetInterface().GetAliasName()
	iface.NativeName = resp.GetInterface().GetNativeName()
	iface.MacAddress = resp.GetInterface().GetMacAddress()
	iface.AdminStatus = agent.DeviceStatus(resp.GetInterface().GetAdminStatus())
	iface.AdminPersistenceVerified = resp.GetInterface().GetAdminPersistenceVerified()
	iface.OperationStatus = agent.DeviceStatus(resp.GetInterface().GetOperationalStatus())
	iface.Status = agent.ProtoStatusToStatus(resp.GetStatus())

	return iface, nil
}

func (c *defaultSwitchAgentClient) GetInterfaceByAbstractName(ctx context.Context, iface *agent.Interface) (*agent.Interface, error) {
	nativeName, err := agent.AbstractNameToNativeName(iface.GetName())
	if err != nil {
		return nil, err
	}

	resp, err := c.client.GetInterface(ctx, &pb.GetInterfaceRequest{
		InterfaceName: nativeName,
	})
	if err != nil {
		return nil, err
	}

	if err := responseError("GetInterface", resp.GetStatus()); err != nil {
		return nil, err
	}
	if resp.GetInterface() == nil {
		return nil, fmt.Errorf("GetInterface: missing interface in agent response")
	}

	return &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name:            resp.GetInterface().Name,
		AliasName:       resp.GetInterface().AliasName,
		NativeName:      resp.GetInterface().NativeName,
		MacAddress:      resp.GetInterface().GetMacAddress(),
		OperationStatus: agent.DeviceStatus(resp.GetInterface().GetOperationalStatus()),
		AdminStatus:     agent.DeviceStatus(resp.GetInterface().GetAdminStatus()),
		Status:          agent.ProtoStatusToStatus(resp.GetStatus()),
	}, nil
}

func (c *defaultSwitchAgentClient) GetInterfaceNeighbor(ctx context.Context, iface *agent.Interface) (*agent.InterfaceNeighbor, error) {
	resp, err := c.client.GetInterfaceNeighbor(ctx, &pb.GetInterfaceNeighborRequest{
		InterfaceName: iface.GetName(),
	})
	if err != nil {
		return nil, err
	}

	if resp.GetStatus() != nil && resp.GetStatus().GetCode() == agenterrors.NOT_FOUND {
		return &agent.InterfaceNeighbor{Status: agent.ProtoStatusToStatus(resp.GetStatus())}, nil
	}
	if err := responseError("GetInterfaceNeighbor", resp.GetStatus()); err != nil {
		return nil, err
	}
	if resp.GetNeighbor() == nil {
		return nil, fmt.Errorf("GetInterfaceNeighbor: missing neighbor in agent response")
	}

	return &agent.InterfaceNeighbor{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceNeighborKind,
		},
		Name:       resp.GetInterface(),
		MacAddress: resp.GetNeighbor().GetMacAddress(),
		SystemName: resp.GetNeighbor().GetSystemName(),
		Handle:     resp.GetNeighbor().GetNeighborInterfaceName(),
		Status:     agent.ProtoStatusToStatus(resp.GetStatus()),
	}, nil
}

func (c *defaultSwitchAgentClient) ListPorts(ctx context.Context) (*agent.PortList, error) {
	resp, err := c.client.ListPorts(ctx, &pb.ListPortsRequest{})
	if err != nil {
		return nil, err
	}
	if err := responseError("ListPorts", resp.GetStatus()); err != nil {
		return nil, err
	}

	ports := make([]agent.Port, len(resp.GetPorts()))
	for i, port := range resp.GetPorts() {
		ports[i] = agent.Port{
			TypeMeta: agent.TypeMeta{
				Kind: agent.PortKind,
			},
			Name:  port.GetName(),
			Alias: port.GetAlias(),
		}
	}

	portList := &agent.PortList{
		TypeMeta: agent.TypeMeta{
			Kind: agent.PortListKind,
		},
		Items:  ports,
		Status: agent.ProtoStatusToStatus(resp.GetStatus()),
	}

	return portList, nil
}

func (c *defaultSwitchAgentClient) SetInterfaceAliasName(ctx context.Context, iface *agent.Interface) (*agent.Interface, error) {
	resp, err := c.client.SetInterfaceAliasName(ctx, &pb.SetInterfaceAliasNameRequest{
		InterfaceName: iface.GetName(),
		AliasName:     iface.AliasName,
	})
	if err != nil {
		fmt.Println("Error occurred while setting interface alias name:", err)
		return nil, err
	}

	if resp.GetStatus().Code != 0 {
		fmt.Println("Error occurred while setting interface alias name:", resp.GetStatus().GetMessage())
		return &agent.Interface{
			Status: agent.ProtoStatusToStatus(resp.GetStatus()),
		}, fmt.Errorf("failed to set interface alias name: %s", resp.GetStatus().GetMessage())
	}

	iface.AdminStatus = agent.DeviceStatus(resp.GetInterface().GetAdminStatus())
	iface.OperationStatus = agent.DeviceStatus(resp.GetInterface().GetOperationalStatus())
	iface.Status = agent.ProtoStatusToStatus(resp.GetStatus())

	return iface, nil
}

func (c *defaultSwitchAgentClient) SaveConfig(ctx context.Context) error {
	resp, err := c.client.SaveConfig(ctx, &pb.SaveConfigRequest{})
	if err != nil {
		return err
	}

	if resp.GetStatus().Code != 0 {
		return fmt.Errorf("failed to save config: %s", resp.GetStatus().GetMessage())
	}

	return nil
}
