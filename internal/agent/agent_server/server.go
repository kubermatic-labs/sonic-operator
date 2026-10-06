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
	port            = flag.Int("port", 50051, "The server port")
	redisAddr       = flag.String("redis-addr", "127.0.0.1:6379", "The Redis address")
	bindAddress     = flag.String("bind-address", "127.0.0.1", "The server bind address")
	readOnly        = flag.Bool("read-only", true, "Only allow explicitly approved read RPCs")
	tlsCertFile     = flag.String("tls-cert-file", "", "Required PEM server certificate file")
	tlsKeyFile      = flag.String("tls-key-file", "", "Required PEM server private key file")
	tlsClientCAFile = flag.String("tls-client-ca-file", "", "Required PEM CA bundle trusted to issue client certificates")
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
			Name:              iface.Name,
			NativeName:        iface.NativeName,
			MacAddress:        "",
			OperationalStatus: string(iface.OperationStatus),
			AdminStatus:       string(iface.AdminStatus),
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
	case pb.SwitchAgentService_GetDeviceInfo_FullMethodName,
		pb.SwitchAgentService_ListInterfaces_FullMethodName,
		pb.SwitchAgentService_ListPorts_FullMethodName,
		pb.SwitchAgentService_GetInterface_FullMethodName,
		pb.SwitchAgentService_GetInterfaceNeighbor_FullMethodName:
		return handler(ctx, req)
	default:
		return nil, grpcstatus.Error(codes.PermissionDenied, "agent is read-only: RPC is not allowed")
	}
}

func newGRPCServer(certFile, keyFile, clientCAFile string, readOnly bool) (*grpc.Server, error) {
	tlsConfig, err := transport.LoadTLSConfig(certFile, keyFile, clientCAFile)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientCAs = tlsConfig.RootCAs
	tlsConfig.RootCAs = nil
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	opts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}
	if readOnly {
		opts = append(opts, grpc.UnaryInterceptor(readOnlyInterceptor),
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
	s, err := newGRPCServer(*tlsCertFile, *tlsKeyFile, *tlsClientCAFile, *readOnly)
	if err != nil {
		log.Fatalf("invalid agent TLS configuration: %v", err)
	}
	defer s.Stop()

	swAgent, err := sonic.NewSonicRedisAgent(*redisAddr)
	if err != nil {
		log.Fatalf("failed to create SonicRedisAgent: %v", err)
	}

	pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(swAgent))

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
