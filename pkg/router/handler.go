// handler.go demonstrates how the Agent Sandbox Router integrates with the Policy Engine.
//
// This file shows the pattern for intercepting ExecuteRequest at the gRPC boundary,
// evaluating the request against policy, and returning PermissionDenied on policy deny.
//
// The integration point is analogous to LSM hooks in the Linux kernel:
//   - LSM: security_file_permission() called before file operations
//   - Agent Policy: Evaluate() called before tool execution
//
// In production, this code would be integrated into the actual router service.
// The patterns shown here are extracted for clarity.
package router

import (
	"context"

	"github.com/golden-agent/golden-agent/pkg/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExecuteRequest represents a tool execution request from an agent.
// In production, this would be the generated proto message.
type ExecuteRequest struct {
	// ToolName is the name of the tool to execute
	ToolName string

	// Parameters are the tool-specific parameters
	Parameters map[string]interface{}

	// Metadata contains agent identity and context
	Metadata RequestMetadata
}

// ExecuteResponse represents the result of a tool execution.
// In production, this would be the generated proto message.
type ExecuteResponse struct {
	// Result is the tool execution result
	Result interface{}

	// Error contains any error message
	Error string
}

// ToolRouter routes tool requests to the appropriate sandbox.
// This is a simplified representation of the actual router.
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
// EXAMPLE USAGE
// ============================================================
//
// func main() {
//     // 1. Create router with policy integration
//     config := DefaultPolicyConfig()
//     config.Mode = policy.Enforcing  // Actually block denied requests
//     router := NewToolRouter(config)
//
//     // 2. Load policies (normally from AgentPolicy CRDs)
//     codingPolicy := policy.CompilePolicy(
//         "coding-assistant-policy",
//         []string{"coding-assistant"},
//         policy.Deny,  // Default deny
//         []policy.ToolPermission{
//             {Tool: "file.read", Action: policy.Allow},
//             {Tool: "file.write", Action: policy.Allow},
//             {Tool: "code.exec", Action: policy.Allow},
//             {Tool: "network.fetch", Action: policy.Deny},  // Explicit deny
//         },
//         policy.Enforcing,
//         "",  // No MTS label
//     )
//     router.LoadPolicy("coding-assistant", codingPolicy)
//
//     // 3. Handle requests
//     req := &ExecuteRequest{
//         ToolName: "file.read",
//         Parameters: map[string]interface{}{
//             "path": "/workspace/main.go",
//         },
//         Metadata: RequestMetadata{
//             AgentType: "coding-assistant",
//             SandboxID: "sandbox-123",
//             TenantID:  "tenant-abc",
//         },
//     }
//
//     resp, err := router.Execute(context.Background(), req)
//     if err != nil {
//         // Check if it's a policy denial
//         if status.Code(err) == codes.PermissionDenied {
//             log.Printf("Policy denied: %v", err)
//         }
//     }
// }
//
// ============================================================
// GRPC SERVER INTEGRATION
// ============================================================
//
// In a full gRPC server implementation, the Execute method would be
// registered as the handler for the ExecuteRequest RPC:
//
// type agentServer struct {
//     pb.UnimplementedAgentServiceServer
//     router *ToolRouter
// }
//
// func (s *agentServer) Execute(ctx context.Context, req *pb.ExecuteRequest) (*pb.ExecuteResponse, error) {
//     // Convert proto request to internal format
//     internalReq := &ExecuteRequest{
//         ToolName: req.GetToolName(),
//         Parameters: extractParameters(req),
//         Metadata: RequestMetadata{
//             AgentType: req.GetMetadata().GetAgentType(),
//             SandboxID: req.GetMetadata().GetSandboxId(),
//             TenantID:  req.GetMetadata().GetTenantId(),
//             SessionID: req.GetMetadata().GetSessionId(),
//             MTSLabel:  req.GetMetadata().GetMtsLabel(),
//         },
//     }
//
//     // Execute with policy enforcement
//     resp, err := s.router.Execute(ctx, internalReq)
//     if err != nil {
//         return nil, err  // gRPC status codes are already set
//     }
//
//     // Convert response back to proto
//     return &pb.ExecuteResponse{...}, nil
// }
