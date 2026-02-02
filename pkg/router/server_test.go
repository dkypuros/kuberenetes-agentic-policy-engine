package router

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentpb "github.com/golden-agent/golden-agent/api/proto/v1alpha1"
	"github.com/golden-agent/golden-agent/pkg/policy"
)

// NOTE: Full gRPC transport tests require protoc-generated code with proper
// ProtoReflect() implementations. The tests below verify the server logic
// directly by calling the Execute method without gRPC transport.
//
// To run full gRPC transport tests:
//   1. Install protoc and protoc-gen-go
//   2. Run: protoc --go_out=. --go-grpc_out=. api/proto/agent.proto
//   3. Use the generated code instead of the hand-written stubs

// mockToolExecutor implements ToolExecutor for testing.
type mockToolExecutor struct {
	result interface{}
	err    error
}

func (m *mockToolExecutor) Execute(ctx context.Context, toolName string, params map[string]interface{}) (interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// TestServerExecuteDirect tests the server Execute method directly (without gRPC transport).
// This verifies the policy enforcement logic without requiring protoc-generated code.
func TestServerExecuteDirect(t *testing.T) {
	// Create server with policy
	config := DefaultServerConfig()
	config.PolicyConfig.Mode = policy.Enforcing
	server := NewServer(config)

	// Load a coding-assistant policy that allows file.read but denies network.fetch
	codingPolicy := policy.CompilePolicy(
		"coding-assistant-policy",
		[]string{"coding-assistant"},
		policy.Deny, // Default deny
		[]policy.ToolPermission{
			{Tool: "file.read", Action: policy.Allow},
			{Tool: "file.write", Action: policy.Allow},
			{Tool: "network.fetch", Action: policy.Deny},
		},
		policy.Enforcing,
		"",
	)
	server.LoadPolicy("coding-assistant", codingPolicy)

	// Set up mock executor
	server.SetToolExecutor(&mockToolExecutor{
		result: map[string]string{"content": "file contents here"},
	})

	ctx := context.Background()

	// Test 1: Allowed tool call (file.read)
	t.Run("allowed_tool", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"path": "/workspace/main.go"})
		resp, err := server.Execute(ctx, &agentpb.ExecuteRequest{
			ToolName:   "file.read",
			Parameters: params,
			Metadata: &agentpb.RequestMetadata{
				AgentType: "coding-assistant",
				SandboxId: "sandbox-123",
				TenantId:  "tenant-abc",
			},
			RequestId: "req-001",
		})

		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if resp.Status != agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
			t.Errorf("expected SUCCESS status, got %v", resp.Status)
		}

		if resp.PolicyDecision.Decision != "ALLOW" {
			t.Errorf("expected ALLOW decision, got %v", resp.PolicyDecision.Decision)
		}

		if resp.RequestId != "req-001" {
			t.Errorf("expected request ID echoed back, got %v", resp.RequestId)
		}
	})

	// Test 2: Denied tool call (network.fetch)
	t.Run("denied_tool", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"url": "https://example.com"})
		resp, err := server.Execute(ctx, &agentpb.ExecuteRequest{
			ToolName:   "network.fetch",
			Parameters: params,
			Metadata: &agentpb.RequestMetadata{
				AgentType: "coding-assistant",
				SandboxId: "sandbox-123",
				TenantId:  "tenant-abc",
			},
			RequestId: "req-002",
		})

		// Should get PERMISSION_DENIED error
		if err == nil {
			t.Fatal("expected PERMISSION_DENIED error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got: %v", err)
		}

		if st.Code() != codes.PermissionDenied {
			t.Errorf("expected PERMISSION_DENIED, got %v", st.Code())
		}

		// Response should still be returned with DENIED status
		if resp == nil {
			t.Fatal("expected response even on denial")
		}

		if resp.Status != agentpb.ExecutionStatus_EXECUTION_STATUS_DENIED {
			t.Errorf("expected DENIED status, got %v", resp.Status)
		}

		if resp.PolicyDecision.Decision != "DENY" {
			t.Errorf("expected DENY decision, got %v", resp.PolicyDecision.Decision)
		}
	})

	// Test 3: Unknown agent type (default deny)
	t.Run("unknown_agent_type", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"path": "/etc/passwd"})
		_, err := server.Execute(ctx, &agentpb.ExecuteRequest{
			ToolName:   "file.read",
			Parameters: params,
			Metadata: &agentpb.RequestMetadata{
				AgentType: "unknown-agent",
				SandboxId: "sandbox-456",
			},
			RequestId: "req-003",
		})

		// Should get PERMISSION_DENIED (no policy loaded for unknown-agent)
		if err == nil {
			t.Fatal("expected PERMISSION_DENIED error for unknown agent type")
		}

		st, _ := status.FromError(err)
		if st.Code() != codes.PermissionDenied {
			t.Errorf("expected PERMISSION_DENIED, got %v", st.Code())
		}
	})

	// Test 4: Tool not in allow list (default deny)
	t.Run("tool_not_in_policy", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"query": "SELECT * FROM users"})
		_, err := server.Execute(ctx, &agentpb.ExecuteRequest{
			ToolName:   "db.query",
			Parameters: params,
			Metadata: &agentpb.RequestMetadata{
				AgentType: "coding-assistant",
				SandboxId: "sandbox-123",
			},
			RequestId: "req-004",
		})

		// Should get PERMISSION_DENIED (db.query not in policy, default is deny)
		if err == nil {
			t.Fatal("expected PERMISSION_DENIED for tool not in policy")
		}

		st, _ := status.FromError(err)
		if st.Code() != codes.PermissionDenied {
			t.Errorf("expected PERMISSION_DENIED, got %v", st.Code())
		}
	})
}

// TestServerValidation tests request validation.
func TestServerValidation(t *testing.T) {
	config := DefaultServerConfig()
	server := NewServer(config)

	ctx := context.Background()

	// Test: Missing tool_name
	t.Run("missing_tool_name", func(t *testing.T) {
		resp, err := server.Execute(ctx, &agentpb.ExecuteRequest{
			ToolName: "",
			Metadata: &agentpb.RequestMetadata{
				AgentType: "coding-assistant",
			},
		})

		if err != nil {
			t.Fatalf("validation should return response, not error: %v", err)
		}

		if resp.Status != agentpb.ExecutionStatus_EXECUTION_STATUS_INVALID {
			t.Errorf("expected INVALID status, got %v", resp.Status)
		}
	})

	// Test: Missing metadata
	t.Run("missing_metadata", func(t *testing.T) {
		resp, err := server.Execute(ctx, &agentpb.ExecuteRequest{
			ToolName: "file.read",
			Metadata: nil,
		})

		if err != nil {
			t.Fatalf("validation should return response, not error: %v", err)
		}

		if resp.Status != agentpb.ExecutionStatus_EXECUTION_STATUS_INVALID {
			t.Errorf("expected INVALID status, got %v", resp.Status)
		}
	})
}

// TestProtobufTypes tests that the protobuf types work correctly.
func TestProtobufTypes(t *testing.T) {
	// Test ExecuteRequest
	params, _ := json.Marshal(map[string]interface{}{
		"path":    "/workspace/test.go",
		"mode":    0644,
		"content": "package main",
	})

	req := &agentpb.ExecuteRequest{
		ToolName:   "file.write",
		Parameters: params,
		Metadata: &agentpb.RequestMetadata{
			AgentType: "coding-assistant",
			SandboxId: "sandbox-123",
			TenantId:  "tenant-abc",
			SessionId: "session-xyz",
			MtsLabel:  "abc123def456",
			Labels: map[string]string{
				"environment": "production",
				"team":        "platform",
			},
		},
		RequestId: "req-test-001",
	}

	// Test getters
	if req.GetToolName() != "file.write" {
		t.Errorf("expected file.write, got %s", req.GetToolName())
	}

	if req.GetMetadata().GetAgentType() != "coding-assistant" {
		t.Errorf("expected coding-assistant, got %s", req.GetMetadata().GetAgentType())
	}

	if req.GetMetadata().GetLabels()["team"] != "platform" {
		t.Errorf("expected platform, got %s", req.GetMetadata().GetLabels()["team"])
	}

	// Test GetParametersMap helper
	paramsMap, err := req.GetParametersMap()
	if err != nil {
		t.Fatalf("GetParametersMap failed: %v", err)
	}

	if paramsMap["path"] != "/workspace/test.go" {
		t.Errorf("expected /workspace/test.go, got %v", paramsMap["path"])
	}

	// Test ExecuteResponse
	resp := &agentpb.ExecuteResponse{
		Status:    agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		Result:    []byte(`{"written": true}`),
		RequestId: "req-test-001",
		PolicyDecision: &agentpb.PolicyDecision{
			Decision:         "Allow",
			PolicyName:       "coding-assistant-policy",
			MatchedRule:      "file.write",
			EvaluationTimeNs: 500,
			CacheHit:         true,
		},
	}

	if resp.GetStatus() != agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		t.Errorf("expected SUCCESS, got %v", resp.GetStatus())
	}

	if resp.GetPolicyDecision().GetCacheHit() != true {
		t.Error("expected cache hit to be true")
	}
}

// TestExecutionStatusString tests the status enum String() method.
func TestExecutionStatusString(t *testing.T) {
	tests := []struct {
		status   agentpb.ExecutionStatus
		expected string
	}{
		{agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, "SUCCESS"},
		{agentpb.ExecutionStatus_EXECUTION_STATUS_DENIED, "DENIED"},
		{agentpb.ExecutionStatus_EXECUTION_STATUS_ERROR, "ERROR"},
		{agentpb.ExecutionStatus_EXECUTION_STATUS_INVALID, "INVALID"},
		{agentpb.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED, "UNSPECIFIED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.status.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.status.String())
			}
		})
	}
}

// TestServerWithExecutor tests the full flow with a tool executor.
func TestServerWithExecutor(t *testing.T) {
	config := DefaultServerConfig()
	config.PolicyConfig.Mode = policy.Enforcing
	server := NewServer(config)

	// Load permissive policy
	testPolicy := policy.CompilePolicy(
		"test-policy",
		[]string{"test-agent"},
		policy.Allow, // Default allow
		nil,
		policy.Enforcing,
		"",
	)
	server.LoadPolicy("test-agent", testPolicy)

	// Set up executor that returns specific result
	expectedResult := map[string]interface{}{
		"data":   "test data",
		"status": "ok",
	}
	server.SetToolExecutor(&mockToolExecutor{
		result: expectedResult,
	})

	ctx := context.Background()
	resp, err := server.Execute(ctx, &agentpb.ExecuteRequest{
		ToolName:   "any.tool",
		Parameters: []byte(`{}`),
		Metadata: &agentpb.RequestMetadata{
			AgentType: "test-agent",
		},
		RequestId: "req-executor-test",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Status != agentpb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		t.Errorf("expected SUCCESS, got %v", resp.Status)
	}

	// Verify result contains expected data
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if result["data"] != "test data" {
		t.Errorf("expected 'test data', got %v", result["data"])
	}
}
