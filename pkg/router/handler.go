// handler.go provides internal types and utilities for policy-enforced tool routing.
//
// This file contains lightweight Go types for internal use (testing, direct embedding).
// For production gRPC communication, see server.go which implements the full
// AgentService using Protocol Buffer types from api/proto/v1alpha1.
//
// Architecture:
//
//	                    ┌─────────────────────────────────────────┐
//	                    │           Router Binary                 │
//	                    │  ┌─────────────────────────────────┐   │
//	Agent ──protobuf──> │  │  gRPC Server (server.go)        │   │
//	                    │  │    │                            │   │
//	                    │  │    v                            │   │
//	                    │  │  Policy Engine                  │   │
//	                    │  │    │                            │   │
//	                    │  │    v                            │   │
//	                    │  │  Tool Executor                  │   │
//	                    │  └─────────────────────────────────┘   │
//	                    └─────────────────────────────────────────┘
//
// The integration point is analogous to LSM hooks in the Linux kernel:
//   - LSM: security_file_permission() called before file operations
//   - Agent Policy: Evaluate() called before tool execution
package router

import (
	"context"

	"github.com/golden-agent/golden-agent/pkg/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExecuteRequest represents a tool execution request (internal format).
// For gRPC/protobuf communication, use agentpb.ExecuteRequest from api/proto/v1alpha1.
type ExecuteRequest struct {
	// ToolName is the name of the tool to execute
	ToolName string

	// Parameters are the tool-specific parameters
	Parameters map[string]interface{}

	// Metadata contains agent identity and context
	Metadata RequestMetadata
}

// ExecuteResponse represents the result of a tool execution (internal format).
// For gRPC/protobuf communication, use agentpb.ExecuteResponse from api/proto/v1alpha1.
type ExecuteResponse struct {
	// Result is the tool execution result
	Result interface{}

	// Error contains any error message
	Error string
}

// ToolRouter routes tool requests with policy enforcement.
// This is the lightweight version for testing and direct embedding.
// For production gRPC servers, use Server from server.go.
type ToolRouter struct {
	policy *RouterPolicyIntegration

	// routeToSandbox is the actual routing function (injected for testing)
	routeToSandbox func(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)
}

// NewToolRouter creates a new router with policy integration.
func NewToolRouter(config PolicyConfig) *ToolRouter {
	return &ToolRouter{
		policy: NewRouterPolicyIntegration(config),
	}
}

// Execute handles a tool execution request.
// This is the main entry point showing the policy integration pattern.
//
// The flow is:
//  1. Extract agent identity from request metadata
//  2. Evaluate the request against policy
//  3. On Deny: return gRPC PermissionDenied immediately
//  4. On Allow: proceed to route the request to the sandbox
//
// This pattern ensures that policy decisions are made BEFORE any tool execution,
// preventing unauthorized actions from ever reaching the sandbox.
func (r *ToolRouter) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	// ============================================================
	// POLICY ENFORCEMENT HOOK
	// This is where Mandatory Access Control is enforced.
	// Every tool request passes through this check.
	// ============================================================

	// Evaluate the request against loaded policies
	decision, err := r.policy.Evaluate(
		ctx,
		req.Metadata,
		req.ToolName,
		req.Parameters,
	)
	if err != nil {
		// Policy evaluation error - fail closed (deny)
		return nil, status.Errorf(codes.Internal,
			"policy evaluation failed: %v", err)
	}

	// Check the policy decision
	if decision == policy.Deny {
		// Policy denied the request - return PermissionDenied
		// The audit event has already been logged by the policy engine
		return nil, status.Errorf(codes.PermissionDenied,
			"tool %q denied by policy for agent type %q",
			req.ToolName, req.Metadata.AgentType)
	}

	// ============================================================
	// POLICY ALLOWED - PROCEED WITH ROUTING
	// At this point, the request has been authorized by policy.
	// Route to the appropriate sandbox for execution.
	// ============================================================

	if r.routeToSandbox == nil {
		// No routing function configured (testing mode)
		return &ExecuteResponse{
			Result: "policy allowed, routing not configured",
		}, nil
	}

	// Route the request to the sandbox
	return r.routeToSandbox(ctx, req)
}

// LoadPolicy adds a policy for an agent type.
// This is called when AgentPolicy CRDs are created or updated.
func (r *ToolRouter) LoadPolicy(agentType string, compiled *policy.CompiledPolicy) {
	r.policy.LoadPolicy(agentType, compiled)
}

// SetRoutingFunction sets the function used to route requests to sandboxes.
// This allows the actual routing logic to be injected.
func (r *ToolRouter) SetRoutingFunction(fn func(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)) {
	r.routeToSandbox = fn
}

// PolicyStats returns statistics about policy enforcement.
func (r *ToolRouter) PolicyStats() (hits, misses uint64, hitRate float64, policies int) {
	return r.policy.Stats()
}

// ============================================================
// EXAMPLE: Using the gRPC Server (Production)
// ============================================================
//
// For production deployments, use the gRPC Server from server.go:
//
//	import (
//	    "net"
//	    agentpb "github.com/golden-agent/golden-agent/api/proto/v1alpha1"
//	    "github.com/golden-agent/golden-agent/pkg/router"
//	    "github.com/golden-agent/golden-agent/pkg/policy"
//	)
//
//	func main() {
//	    // 1. Create gRPC server with embedded policy engine
//	    config := router.DefaultServerConfig()
//	    config.PolicyConfig.Mode = policy.Enforcing
//	    server := router.NewServer(config)
//
//	    // 2. Load policies (normally from AgentPolicy CRDs via controller)
//	    codingPolicy := policy.CompilePolicy(
//	        "coding-assistant-policy",
//	        []string{"coding-assistant"},
//	        policy.Deny,
//	        []policy.ToolPermission{
//	            {Tool: "file.read", Action: policy.Allow},
//	            {Tool: "file.write", Action: policy.Allow},
//	        },
//	        policy.Enforcing,
//	        "",
//	    )
//	    server.LoadPolicy("coding-assistant", codingPolicy)
//
//	    // 3. Start listening for gRPC connections
//	    lis, _ := net.Listen("tcp", ":50051")
//	    server.Serve(lis)
//	}
//
// Agents connect using the gRPC client:
//
//	conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
//	client := agentpb.NewAgentServiceClient(conn)
//
//	resp, err := client.Execute(ctx, &agentpb.ExecuteRequest{
//	    ToolName:   "file.read",
//	    Parameters: []byte(`{"path": "/workspace/main.go"}`),
//	    Metadata: &agentpb.RequestMetadata{
//	        AgentType: "coding-assistant",
//	        SandboxId: "sandbox-123",
//	        TenantId:  "tenant-abc",
//	    },
//	})
//
// ============================================================
// EXAMPLE: Using ToolRouter (Testing/Embedding)
// ============================================================
//
// For testing or direct embedding without gRPC:
//
//	config := router.DefaultPolicyConfig()
//	config.Mode = policy.Enforcing
//	r := router.NewToolRouter(config)
//
//	// Load policy
//	r.LoadPolicy("coding-assistant", codingPolicy)
//
//	// Execute directly (no network)
//	resp, err := r.Execute(ctx, &router.ExecuteRequest{
//	    ToolName: "file.read",
//	    Parameters: map[string]interface{}{"path": "/workspace/main.go"},
//	    Metadata: router.RequestMetadata{
//	        AgentType: "coding-assistant",
//	    },
//	})
