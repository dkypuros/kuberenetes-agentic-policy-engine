// Package router provides the gRPC server implementation for the Golden Agent.
//
// The server embeds the policy engine and enforces mandatory access control
// on every tool call. This is the binary-to-binary interface that agents use
// to communicate with the router - all communication happens via Protocol Buffers
// over gRPC, ensuring efficient binary serialization.
//
// Architecture:
//
//	Agent (gRPC Client) ──protobuf──> Router (gRPC Server) ──> Policy Engine ──> Tool Executor
//	                                         │
//	                                    Binary-to-binary
//	                                    communication
//
// The policy check happens BEFORE any tool execution, implementing the same
// pattern as SELinux's LSM hooks in the Linux kernel.
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentpb "github.com/golden-agent/golden-agent/api/proto/v1alpha1"
	"github.com/golden-agent/golden-agent/pkg/policy"
)

// Server implements the AgentService gRPC server.
// It embeds the policy engine and routes tool calls to executors.
type Server struct {
	agentpb.UnimplementedAgentServiceServer

	// policy is the embedded policy integration layer.
	policy *RouterPolicyIntegration

	// toolExecutor executes tool calls after policy approval.
	toolExecutor ToolExecutor

	// grpcServer is the underlying gRPC server.
	grpcServer *grpc.Server
}

// ToolExecutor is the interface for executing tool calls.
// Implementations handle the actual tool logic (file I/O, code execution, etc.).
type ToolExecutor interface {
	// Execute runs a tool and returns the result.
	Execute(ctx context.Context, toolName string, parameters map[string]interface{}) (interface{}, error)
}

// ServerConfig contains configuration for the gRPC server.
type ServerConfig struct {
	// PolicyConfig is the configuration for the embedded policy engine.
	PolicyConfig PolicyConfig

	// MaxRecvMsgSize is the maximum message size in bytes (default: 4MB).
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum send message size in bytes (default: 4MB).
	MaxSendMsgSize int
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		PolicyConfig:   DefaultPolicyConfig(),
		MaxRecvMsgSize: 4 * 1024 * 1024, // 4MB
		MaxSendMsgSize: 4 * 1024 * 1024, // 4MB
	}
}

// NewServer creates a new gRPC server with embedded policy engine.
func NewServer(config ServerConfig) *Server {
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(config.MaxSendMsgSize),
	}

	s := &Server{
		policy:     NewRouterPolicyIntegration(config.PolicyConfig),
		grpcServer: grpc.NewServer(opts...),
	}

	// Register the AgentService with the gRPC server
	agentpb.RegisterAgentServiceServer(s.grpcServer, s)

	return s
}

// SetToolExecutor sets the tool executor for handling approved requests.
func (s *Server) SetToolExecutor(executor ToolExecutor) {
	s.toolExecutor = executor
}

// LoadPolicy adds a policy for an agent type.
func (s *Server) LoadPolicy(agentType string, compiled *policy.CompiledPolicy) {
	s.policy.LoadPolicy(agentType, compiled)
}

// Serve starts the gRPC server on the given listener.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// GracefulStop stops the server gracefully.
func (s *Server) GracefulStop() {
	s.grpcServer.GracefulStop()
}

// Execute implements the AgentService.Execute RPC.
// This is the main entry point for all tool calls from agents.
//
// The flow is:
//  1. Decode the protobuf request
//  2. Extract agent identity from metadata
//  3. Evaluate the request against policy
//  4. On Deny: return gRPC PERMISSION_DENIED
//  5. On Allow: execute the tool and return the result
func (s *Server) Execute(ctx context.Context, req *agentpb.ExecuteRequest) (*agentpb.ExecuteResponse, error) {
	startTime := time.Now()

	// Validate request
	if req.GetToolName() == "" {
		return &agentpb.ExecuteResponse{
			Status:    agentpb.ExecutionStatus_EXECUTION_STATUS_INVALID,
			Error:     "tool_name is required",
			RequestId: req.GetRequestId(),
		}, nil
	}

	if req.GetMetadata() == nil {
		return &agentpb.ExecuteResponse{
			Status:    agentpb.ExecutionStatus_EXECUTION_STATUS_INVALID,
			Error:     "metadata is required",
			RequestId: req.GetRequestId(),
		}, nil
	}

	// Convert protobuf metadata to internal format
	metadata := RequestMetadata{
		AgentType: req.GetMetadata().GetAgentType(),
		SandboxID: req.GetMetadata().GetSandboxId(),
		TenantID:  req.GetMetadata().GetTenantId(),
		SessionID: req.GetMetadata().GetSessionId(),
		MTSLabel:  req.GetMetadata().GetMtsLabel(),
	}

	// Decode parameters from JSON bytes
	params, err := req.GetParametersMap()
	if err != nil {
		return &agentpb.ExecuteResponse{
			Status:    agentpb.ExecutionStatus_EXECUTION_STATUS_INVALID,
			Error:     fmt.Sprintf("invalid parameters JSON: %v", err),
			RequestId: req.GetRequestId(),
		}, nil
	}

	// ============================================================
	// POLICY ENFORCEMENT HOOK
	// This is where Mandatory Access Control is enforced.
	// Every tool request passes through this check.
	// ============================================================

	decision, err := s.policy.Evaluate(ctx, metadata, req.GetToolName(), params)
	evalTime := time.Since(startTime)

	if err != nil {
		// Policy evaluation error - fail closed (deny)
		return nil, status.Errorf(codes.Internal, "policy evaluation failed: %v", err)
	}

	// Build policy decision for response
	policyDecision := &agentpb.PolicyDecision{
		Decision:         decision.String(),
		EvaluationTimeNs: evalTime.Nanoseconds(),
	}

	// Check the policy decision
	if decision == policy.Deny {
		// Policy denied the request - return PERMISSION_DENIED
		return &agentpb.ExecuteResponse{
			Status:         agentpb.ExecutionStatus_EXECUTION_STATUS_DENIED,
			Error:          fmt.Sprintf("tool %q denied by policy for agent type %q", req.GetToolName(), metadata.AgentType),
			RequestId:      req.GetRequestId(),
			PolicyDecision: policyDecision,
		}, status.Errorf(codes.PermissionDenied,
			"tool %q denied by policy for agent type %q",
			req.GetToolName(), metadata.AgentType)
	}

	// ============================================================
	// POLICY ALLOWED - PROCEED WITH EXECUTION
	// At this point, the request has been authorized by policy.
	// ============================================================

	if s.toolExecutor == nil {
		// No executor configured - return success with placeholder
		return &agentpb.ExecuteResponse{
			Status:         agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
			Result:         []byte(`{"message":"policy allowed, tool executor not configured"}`),
			RequestId:      req.GetRequestId(),
			PolicyDecision: policyDecision,
		}, nil
	}

	// Execute the tool
	result, err := s.toolExecutor.Execute(ctx, req.GetToolName(), params)
	if err != nil {
		return &agentpb.ExecuteResponse{
			Status:         agentpb.ExecutionStatus_EXECUTION_STATUS_ERROR,
			Error:          err.Error(),
			RequestId:      req.GetRequestId(),
			PolicyDecision: policyDecision,
		}, nil
	}

	// Encode result as JSON
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return &agentpb.ExecuteResponse{
			Status:         agentpb.ExecutionStatus_EXECUTION_STATUS_ERROR,
			Error:          fmt.Sprintf("failed to encode result: %v", err),
			RequestId:      req.GetRequestId(),
			PolicyDecision: policyDecision,
		}, nil
	}

	return &agentpb.ExecuteResponse{
		Status:         agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		Result:         resultBytes,
		RequestId:      req.GetRequestId(),
		PolicyDecision: policyDecision,
	}, nil
}

// PolicyStats returns statistics about policy enforcement.
func (s *Server) PolicyStats() (hits, misses uint64, hitRate float64, policies int) {
	return s.policy.Stats()
}
