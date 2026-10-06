// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"

	hp "github.com/ironcore-dev/sonic-operator/internal/agent/hostproto"
	"github.com/ironcore-dev/sonic-operator/internal/agent/transport"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"

	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	"github.com/ironcore-dev/sonic-operator/internal/agent/sonic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcstatus "google.golang.org/grpc/status"
)

var (
	port                    = flag.Int("port", 50051, "The server port")
	redisAddr               = flag.String("redis-addr", "127.0.0.1:6379", "The Redis address")
	bindAddress             = flag.String("bind-address", "127.0.0.1", "The server bind address")
	readOnly                = flag.Bool("read-only", true, "Only allow explicitly approved read RPCs")
	tlsCertFile             = flag.String("tls-cert-file", "", "Required PEM server certificate file")
	tlsKeyFile              = flag.String("tls-key-file", "", "Required PEM server private key file")
	tlsClientCAFile         = flag.String("tls-client-ca-file", "", "Required PEM CA bundle trusted to issue client certificates")
	allowAuthoritativeVLANs = flag.Bool("allow-authoritative-vlans", false, "Allow authoritative VLAN reconciliation and ownership release when read-only is disabled")
	vlanAuthorityJournalDir = flag.String("vlan-authority-journal-dir", "", "Persistent root-only VLAN authority journal directory; required for authoritative writes")
	allowBreakout           = flag.Bool("allow-breakout", false, "Allow port breakout reconciliation when read-only is disabled")
	breakoutJournalDir      = flag.String("breakout-journal-dir", "", "Private persistent absolute breakout journal directory; required for breakout writes")
	allowNetworkConfig      = flag.Bool("allow-network-config", false, "Allow network configuration when read-only is disabled")
	allowFRRMigration       = flag.Bool("allow-frr-migration", false, "Allow FRR migration when network configuration is enabled and read-only is disabled")
	allowTrafficPolicy      = flag.Bool("allow-traffic-policy", false, "Allow ACL and QoS configuration when network configuration is enabled and read-only is disabled")
	allowRedundancy         = flag.Bool("allow-redundancy", false, "Allow MLAG and EVPN/VXLAN configuration when network configuration is enabled and read-only is disabled")
	networkJournalDir       = flag.String("network-journal-dir", "", "Private persistent absolute network journal directory; required for network writes and all cooperating writers after first use")
)

type proxyServer struct {
	pb.UnimplementedSwitchAgentServiceServer

	SwitchAgent switchAgent.SwitchAgent
}

func (s *proxyServer) GetDeviceInfo(ctx context.Context, request *pb.GetDeviceInfoRequest) (*pb.GetDeviceInfoResponse, error) {
	log.Printf("GetDeviceInfo called")

	// Fetch device info from the SwitchAgent
	device, status := s.SwitchAgent.GetDeviceInfo(ctx)
	if status != nil {
		return &pb.GetDeviceInfoResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: status.Message,
			},
		}, nil
	}

	if device == nil {
		return nil, grpcstatus.Error(codes.Internal, "backend returned no device information")
	}
	return &pb.GetDeviceInfoResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		LocalMacAddress: device.LocalMacAddress,
		Hwsku:           device.Hwsku,
		SonicOsVersion:  device.SonicOSVersion,
		AsicType:        device.AsicType,
		Readiness:       device.Readiness,
	}, nil
}

func (s *proxyServer) ListInterfaces(ctx context.Context, request *pb.ListInterfacesRequest) (*pb.ListInterfacesResponse, error) {
	log.Printf("ListInterfaces called")

	interfaceList, status := s.SwitchAgent.ListInterfaces(ctx)
	if status != nil {
		return &pb.ListInterfacesResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: fmt.Sprintf("failed to list interfaces: %v", status.Message),
			},
		}, nil
	}

	if interfaceList == nil {
		return nil, grpcstatus.Error(codes.Internal, "backend returned no interface list")
	}
	var interfaces = make([]*pb.Interface, 0, len(interfaceList.Items))
	for _, iface := range interfaceList.Items {
		interfaces = append(interfaces, &pb.Interface{
			Name:              iface.Name,
			NativeName:        iface.NativeName,
			AliasName:         iface.AliasName,
			MacAddress:        iface.MacAddress,
			OperationalStatus: string(iface.OperationStatus),
			AdminStatus:       string(iface.AdminStatus),
		})
	}

	return &pb.ListInterfacesResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		Interfaces: interfaces,
	}, nil
}

func (s *proxyServer) SetInterfaceAdminStatus(ctx context.Context, request *pb.SetInterfaceAdminStatusRequest) (*pb.SetInterfaceAdminStatusResponse, error) {
	log.Printf("SetInterfaceAdminStatus called: interface=%s, status=%s", request.GetInterfaceName(), request.GetAdminStatus())

	iface, status := s.SwitchAgent.SetInterfaceAdminStatus(ctx, &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name:        request.GetInterfaceName(),
		AdminStatus: agent.DeviceStatus(request.GetAdminStatus()),
	})

	if status != nil {
		return &pb.SetInterfaceAdminStatusResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: status.Message,
			},
		}, nil
	}

	return &pb.SetInterfaceAdminStatusResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		Interface: &pb.Interface{
			Name:                     iface.Name,
			NativeName:               iface.NativeName,
			MacAddress:               "",
			OperationalStatus:        string(iface.OperationStatus),
			AdminStatus:              string(iface.AdminStatus),
			AdminPersistenceVerified: iface.AdminPersistenceVerified,
		},
	}, nil
}

func (s *proxyServer) ListPorts(ctx context.Context, request *pb.ListPortsRequest) (*pb.ListPortsResponse, error) {
	log.Printf("ListPorts called")

	portList, status := s.SwitchAgent.ListPorts(ctx)
	if status != nil {
		return &pb.ListPortsResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: fmt.Sprintf("failed to list ports: %v", status.Message),
			},
		}, nil
	}

	if portList == nil {
		return nil, grpcstatus.Error(codes.Internal, "backend returned no port list")
	}
	var ports = make([]*pb.Port, 0, len(portList.Items))
	for _, port := range portList.Items {
		ports = append(ports, &pb.Port{
			Name:  port.Name,
			Alias: port.Alias,
		})
	}

	return &pb.ListPortsResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		Ports: ports,
	}, nil
}

func (s *proxyServer) GetInterface(ctx context.Context, request *pb.GetInterfaceRequest) (*pb.GetInterfaceResponse, error) {
	log.Printf("GetInterface called: interface=%s", request.GetInterfaceName())

	iface, status := s.SwitchAgent.GetInterface(ctx, &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name: request.GetInterfaceName(),
	})
	if status != nil {
		return &pb.GetInterfaceResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: fmt.Sprintf("failed to get interface: %v", status.Message),
			},
		}, nil
	}

	if iface == nil {
		return nil, grpcstatus.Error(codes.Internal, "backend returned no interface")
	}
	return &pb.GetInterfaceResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		Interface: &pb.Interface{
			Name:              iface.Name,
			NativeName:        iface.NativeName,
			AliasName:         iface.AliasName,
			MacAddress:        iface.MacAddress,
			OperationalStatus: string(iface.OperationStatus),
			AdminStatus:       string(iface.AdminStatus),
		},
	}, nil
}

func (s *proxyServer) SetInterfaceAliasName(ctx context.Context, request *pb.SetInterfaceAliasNameRequest) (*pb.SetInterfaceAliasNameResponse, error) {
	log.Printf("SetInterfaceAliasName called: interface=%s, alias=%s", request.GetInterfaceName(), request.GetAliasName())

	iface, status := s.SwitchAgent.SetInterfaceAliasName(ctx, &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name:      request.GetInterfaceName(),
		AliasName: request.GetAliasName(),
	})

	if status != nil {
		return &pb.SetInterfaceAliasNameResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: status.Message,
			},
		}, nil
	}

	return &pb.SetInterfaceAliasNameResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		Interface: &pb.Interface{
			Name:              iface.Name,
			AliasName:         iface.AliasName,
			NativeName:        iface.GetNativeName(),
			MacAddress:        "",
			OperationalStatus: string(iface.OperationStatus),
			AdminStatus:       string(iface.AdminStatus),
		},
	}, nil
}

func (s *proxyServer) GetInterfaceNeighbor(ctx context.Context, request *pb.GetInterfaceNeighborRequest) (*pb.GetInterfaceNeighborResponse, error) {
	log.Printf("GetInterfaceNeighbor called: interface=%s", request.GetInterfaceName())

	ifaceNeighbor, status := s.SwitchAgent.GetInterfaceNeighbor(ctx, &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name: request.GetInterfaceName(),
	})
	if status != nil {
		return &pb.GetInterfaceNeighborResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: fmt.Sprintf("failed to get interface neighbor: %v", status.Message),
			},
		}, nil
	}

	if ifaceNeighbor == nil {
		return nil, grpcstatus.Error(codes.Internal, "backend returned no interface neighbor")
	}
	return &pb.GetInterfaceNeighborResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
		Interface: request.GetInterfaceName(),
		Neighbor: &pb.InterfaceNeighbor{
			MacAddress:            ifaceNeighbor.MacAddress,
			NeighborInterfaceName: ifaceNeighbor.Handle,
			SystemName:            ifaceNeighbor.SystemName,
		},
	}, nil
}

func (s *proxyServer) SaveConfig(ctx context.Context, request *pb.SaveConfigRequest) (*pb.SaveConfigResponse, error) {
	log.Printf("SaveConfig called")

	status := s.SwitchAgent.SaveConfig(ctx)
	if status != nil {
		return &pb.SaveConfigResponse{
			Status: &pb.Status{
				Code:    status.Code,
				Message: fmt.Sprintf("failed to save config: %v", status.Message),
			},
		}, nil
	}

	return &pb.SaveConfigResponse{
		Status: &pb.Status{
			Code:    0,
			Message: "Success",
		},
	}, nil
}

// NewProxyServer creates a proxyServer backed by the given SwitchAgent.
// This is exported so tests can instantiate a server with a fake agent.
func NewProxyServer(switchAgentImpl switchAgent.SwitchAgent) pb.SwitchAgentServiceServer {
	return &proxyServer{SwitchAgent: switchAgentImpl}
}

func readOnlyInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	switch info.FullMethod {
	case hp.HostService_Get_FullMethodName,
		pb.SwitchAgentService_GetDeviceInfo_FullMethodName,
		pb.SwitchAgentService_ListInterfaces_FullMethodName,
		pb.SwitchAgentService_ListPorts_FullMethodName,
		pb.SwitchAgentService_GetInterface_FullMethodName,
		pb.SwitchAgentService_GetVLAN_FullMethodName,
		pb.SwitchAgentService_GetVLANAuthority_FullMethodName,
		pb.SwitchAgentService_GetPortBreakout_FullMethodName,
		pb.SwitchAgentService_GetNetworkResource_FullMethodName,
		pb.SwitchAgentService_GetInterfaceNeighbor_FullMethodName:
		return handler(ctx, req)
	default:
		return nil, grpcstatus.Error(codes.PermissionDenied, "agent is read-only: RPC is not allowed")
	}
}

func newGRPCServer(certFile, keyFile, clientCAFile string, readOnly bool, allowAuthoritative ...bool) (*grpc.Server, error) {
	return newGRPCServerWithBreakout(certFile, keyFile, clientCAFile, readOnly, len(allowAuthoritative) == 1 && allowAuthoritative[0], false)
}

func newGRPCServerWithBreakout(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout bool) (*grpc.Server, error) {
	return newGRPCServerWithNetwork(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, false)
}

func newGRPCServerWithNetwork(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork bool) (*grpc.Server, error) {
	return newGRPCServerWithFRRMigration(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, false)
}

// Migration always requires its own explicit opt-in, including for journal recovery.
func newGRPCServerWithFRRMigration(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration bool) (*grpc.Server, error) {
	return newGRPCServerWithTrafficPolicy(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, false)
}

// Traffic policy requires an independent opt-in for both Ensure and Recover.
func newGRPCServerWithTrafficPolicy(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic bool) (*grpc.Server, error) {
	return newGRPCServerWithRedundancy(certFile, keyFile, clientCAFile, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic, false)
}

// Redundancy requires an independent opt-in for both Ensure and Recover.
func newGRPCServerWithRedundancy(certFile, keyFile, clientCAFile string, readOnly, allowAuthoritative, allowBreakout, allowNetwork, allowMigration, allowTraffic, allowRedundancy bool) (*grpc.Server, error) {
	tlsConfig, err := transport.LoadTLSConfig(certFile, keyFile, clientCAFile)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientCAs = tlsConfig.RootCAs
	tlsConfig.RootCAs = nil
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	opts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.StatsHandler(hostConnectionStats{})}
	allow := allowAuthoritative && !readOnly
	opts = append(opts, grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		switch info.FullMethod {
		case pb.SwitchAgentService_EnsureNetworkResource_FullMethodName, pb.SwitchAgentService_RecoverNetworkResource_FullMethodName:
			if !allowNetwork || readOnly {
				return nil, grpcstatus.Error(codes.PermissionDenied, "network configuration requires --allow-network-config=true and --read-only=false")
			}
			// Gate the envelope kind before spec parsing. Noncanonical kinds are
			// rejected by ValidateNetworkRequest before any backend dispatch.
			r, ok := req.(*pb.NetworkRequest)
			if !ok || r == nil {
				return nil, grpcstatus.Error(codes.InvalidArgument, "network request required")
			}
			if r.GetKind() == "FRRMigration" && !allowMigration {
				return nil, grpcstatus.Error(codes.PermissionDenied, "FRR migration requires --allow-frr-migration=true")
			}
			switch r.GetKind() {
			case "MLAG", "VXLANTunnel", "VLANVNI", "EVPNPeer", "EVPN":
				if !allowRedundancy {
					return nil, grpcstatus.Error(codes.PermissionDenied, "redundancy requires --allow-redundancy=true")
				}
			case "ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding":
				if !allowTraffic {
					return nil, grpcstatus.Error(codes.PermissionDenied, "traffic policy requires --allow-traffic-policy=true")
				}
			}
		case pb.SwitchAgentService_ReconcileVLANAuthority_FullMethodName, pb.SwitchAgentService_ReleaseVLANAuthority_FullMethodName:
			if !allow {
				return nil, grpcstatus.Error(codes.PermissionDenied, "authoritative VLANs require --allow-authoritative-vlans=true and --read-only=false")
			}
		case pb.SwitchAgentService_ReconcilePortBreakout_FullMethodName:
			if !allowBreakout || readOnly {
				return nil, grpcstatus.Error(codes.PermissionDenied, "port breakout requires --allow-breakout=true and --read-only=false")
			}
		}
		return handler(ctx, req)
	}))
	if readOnly {
		opts = append(opts, grpc.ChainUnaryInterceptor(readOnlyInterceptor),
			// No streaming RPCs are approved, including reflection and unknown methods.
			grpc.StreamInterceptor(func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
				return grpcstatus.Error(codes.PermissionDenied, "agent is read-only: streaming RPCs are not allowed")
			}),
			grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
				return grpcstatus.Error(codes.PermissionDenied, "agent is read-only: unknown RPC is not allowed")
			}),
		)
	}
	return grpc.NewServer(opts...), nil
}

func StartServer() {
	flag.Parse()

	// Validate security configuration before opening a listener or contacting the backend.
	s, err := newGRPCServerWithRedundancy(*tlsCertFile, *tlsKeyFile, *tlsClientCAFile, *readOnly, *allowAuthoritativeVLANs, *allowBreakout, *allowNetworkConfig, *allowFRRMigration, *allowTrafficPolicy, *allowRedundancy)
	if err != nil {
		log.Fatalf("invalid agent TLS configuration: %v", err)
	}
	defer s.Stop()
	if *allowAuthoritativeVLANs && !*readOnly && *vlanAuthorityJournalDir == "" {
		log.Fatal("--vlan-authority-journal-dir is required when authoritative VLANs are enabled")
	}
	if *allowBreakout && !*readOnly && *breakoutJournalDir == "" {
		log.Fatal("--breakout-journal-dir is required when breakout writes are enabled")
	}
	if *allowNetworkConfig && !*readOnly && *networkJournalDir == "" {
		log.Fatal("--network-journal-dir is required when network writes are enabled")
	}

	swAgent, err := sonic.NewSonicRedisAgent(*redisAddr)
	if err != nil {
		log.Fatalf("failed to create SonicRedisAgent: %v", err)
	}
	if err := configureVLANAuthorityJournal(swAgent, *vlanAuthorityJournalDir, *allowAuthoritativeVLANs, *readOnly); err != nil {
		log.Fatalf("invalid VLAN authority journal configuration: %v", err)
	}
	if err := configureBreakoutJournal(swAgent, *breakoutJournalDir, *allowBreakout, *readOnly); err != nil {
		log.Fatalf("invalid breakout journal configuration: %v", err)
	}
	if err := configureNetworkJournal(swAgent, *networkJournalDir, *allowNetworkConfig, *readOnly); err != nil {
		log.Fatalf("invalid network journal configuration: %v", err)
	}

	pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(swAgent))
	if err := registerHost(s, swAgent); err != nil {
		log.Fatal("host recovery initialization failed")
	}

	lis, err := net.Listen("tcp", net.JoinHostPort(*bindAddress, strconv.Itoa(*port)))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	log.Printf("gRPC server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
