package policy

import (
	"context"
	"testing"
	"time"
)

// TestEngineBasicAllow verifies that allowed tools pass
func TestEngineBasicAllow(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	// Load a policy that allows file.read
	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny, // default deny
		[]ToolPermission{
			{Tool: "file.read", Action: Allow},
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	// Create agent context
	agent := AgentContext{
		AgentType: "coding-assistant",
		SandboxID: "sandbox-123",
	}

	// Test allowed tool
	decision, err := engine.Evaluate(context.Background(), agent, "file.read", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != Allow {
		t.Errorf("expected Allow, got %v", decision)
	}
}

// TestEngineBasicDeny verifies that denied tools are blocked
func TestEngineBasicDeny(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny,
		[]ToolPermission{
			{Tool: "file.read", Action: Allow},
			{Tool: "shell.execute", Action: Deny},
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	agent := AgentContext{
		AgentType: "coding-assistant",
	}

	// Test explicitly denied tool
	decision, err := engine.Evaluate(context.Background(), agent, "shell.execute", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != Deny {
		t.Errorf("expected Deny for shell.execute, got %v", decision)
	}

	// Test tool not in policy (should use default deny)
	decision, err = engine.Evaluate(context.Background(), agent, "db.admin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != Deny {
		t.Errorf("expected Deny for unlisted tool, got %v", decision)
	}
}

// TestEngineDefaultAllow verifies default-allow policies
func TestEngineDefaultAllow(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	policy := CompilePolicy(
		"permissive-policy",
		[]string{"trusted-agent"},
		Allow, // default allow
		[]ToolPermission{
			{Tool: "db.admin", Action: Deny}, // explicitly deny this one
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("trusted-agent", policy)

	agent := AgentContext{
		AgentType: "trusted-agent",
	}

	// Unlisted tool should be allowed
	decision, _ := engine.Evaluate(context.Background(), agent, "file.write", nil)
	if decision != Allow {
		t.Errorf("expected Allow for unlisted tool with default-allow, got %v", decision)
	}

	// Explicitly denied tool should still be denied
	decision, _ = engine.Evaluate(context.Background(), agent, "db.admin", nil)
	if decision != Deny {
		t.Errorf("expected Deny for explicitly denied tool, got %v", decision)
	}
}

// TestEnginePermissiveMode verifies permissive mode logs but allows
func TestEnginePermissiveMode(t *testing.T) {
	engine := NewEngine(WithMode(Permissive))

	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny,
		[]ToolPermission{},
		Permissive,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	agent := AgentContext{
		AgentType: "coding-assistant",
	}

	// In permissive mode, even denied tools return Allow
	decision, _ := engine.Evaluate(context.Background(), agent, "shell.execute", nil)
	if decision != Allow {
		t.Errorf("permissive mode should return Allow even for denied tools, got %v", decision)
	}
}

// TestEngineNoPolicy verifies behavior when no policy exists
func TestEngineNoPolicy(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	agent := AgentContext{
		AgentType: "unknown-agent",
	}

	// No policy should result in Deny
	decision, _ := engine.Evaluate(context.Background(), agent, "any.tool", nil)
	if decision != Deny {
		t.Errorf("expected Deny when no policy exists, got %v", decision)
	}
}

// TestEngineCacheHit verifies cache improves performance
func TestEngineCacheHit(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny,
		[]ToolPermission{
			{Tool: "file.read", Action: Allow},
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	agent := AgentContext{
		AgentType: "coding-assistant",
	}

	// First call - cache miss
	engine.Evaluate(context.Background(), agent, "file.read", nil)

	// Second call - should be cache hit
	engine.Evaluate(context.Background(), agent, "file.read", nil)

	hits, misses, hitRate := engine.CacheStats()
	if hits != 1 {
		t.Errorf("expected 1 cache hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 cache miss, got %d", misses)
	}
	if hitRate != 50.0 {
		t.Errorf("expected 50%% hit rate, got %.1f%%", hitRate)
	}
}

// TestEngineCacheInvalidation verifies cache is cleared on policy update
func TestEngineCacheInvalidation(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Allow,
		[]ToolPermission{},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	agent := AgentContext{
		AgentType: "coding-assistant",
	}

	// Populate cache
	engine.Evaluate(context.Background(), agent, "file.read", nil)

	// Update policy to deny
	newPolicy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny,
		[]ToolPermission{},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", newPolicy)

	// Should use new policy (cache was invalidated)
	decision, _ := engine.Evaluate(context.Background(), agent, "file.read", nil)
	if decision != Deny {
		t.Errorf("expected Deny after policy update, got %v", decision)
	}
}

// TestEnginePathConstraints verifies file path constraints
func TestEnginePathConstraints(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny,
		[]ToolPermission{
			{
				Tool:   "file.read",
				Action: Allow,
				Constraints: &ToolConstraints{
					PathPatterns: []string{"/workspace/**", "/tmp/*"},
				},
			},
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	agent := AgentContext{
		AgentType: "coding-assistant",
	}

	tests := []struct {
		path     string
		expected Decision
	}{
		{"/workspace/src/main.go", Allow},
		{"/workspace/deep/nested/file.txt", Allow},
		{"/tmp/scratch", Allow},
		{"/etc/passwd", Deny},
		{"/home/user/secrets", Deny},
	}

	for _, tt := range tests {
		// Clear cache for each test
		engine.cache.InvalidateAll()

		request := map[string]interface{}{"path": tt.path}
		decision, _ := engine.Evaluate(context.Background(), agent, "file.read", request)
		if decision != tt.expected {
			t.Errorf("path %s: expected %v, got %v", tt.path, tt.expected, decision)
		}
	}
}

// TestEngineDomainConstraints verifies network domain constraints
func TestEngineDomainConstraints(t *testing.T) {
	engine := NewEngine(WithMode(Enforcing))

	policy := CompilePolicy(
		"test-policy",
		[]string{"research-agent"},
		Deny,
		[]ToolPermission{
			{
				Tool:   "network.fetch",
				Action: Allow,
				Constraints: &ToolConstraints{
					AllowedDomains: []string{"*.github.com", "api.example.com"},
				},
			},
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("research-agent", policy)

	agent := AgentContext{
		AgentType: "research-agent",
	}

	tests := []struct {
		domain   string
		expected Decision
	}{
		{"api.github.com", Allow},
		{"raw.github.com", Allow},
		{"api.example.com", Allow},
		{"evil.com", Deny},
		{"github.com.evil.com", Deny},
	}

	for _, tt := range tests {
		engine.cache.InvalidateAll()

		request := map[string]interface{}{"domain": tt.domain}
		decision, _ := engine.Evaluate(context.Background(), agent, "network.fetch", request)
		if decision != tt.expected {
			t.Errorf("domain %s: expected %v, got %v", tt.domain, tt.expected, decision)
		}
	}
}

// TestDecisionCacheTTL verifies cache entries expire
func TestDecisionCacheTTL(t *testing.T) {
	cache := NewDecisionCache(50 * time.Millisecond)

	cache.Set("test:key", Allow, "test")

	// Should hit immediately
	_, _, ok := cache.Get("test:key")
	if !ok {
		t.Error("expected cache hit")
	}

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	// Should miss after TTL
	_, _, ok = cache.Get("test:key")
	if ok {
		t.Error("expected cache miss after TTL")
	}
}

// TestAuditSink verifies audit events are emitted
func TestAuditSink(t *testing.T) {
	var events []*AuditEvent
	sink := &testAuditSink{events: &events}

	engine := NewEngine(WithMode(Enforcing), WithAuditSink(sink))

	policy := CompilePolicy(
		"test-policy",
		[]string{"coding-assistant"},
		Deny,
		[]ToolPermission{
			{Tool: "file.read", Action: Allow},
		},
		Enforcing,
		"",
	)
	engine.LoadPolicy("coding-assistant", policy)

	agent := AgentContext{
		AgentType: "coding-assistant",
		SandboxID: "sandbox-123",
	}

	engine.Evaluate(context.Background(), agent, "file.read", nil)
	engine.Evaluate(context.Background(), agent, "file.write", nil)

	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}

	if events[0].Decision != Allow {
		t.Errorf("first event should be Allow")
	}
	if events[1].Decision != Deny {
		t.Errorf("second event should be Deny")
	}
}

// testAuditSink is a simple audit sink for testing
type testAuditSink struct {
	events *[]*AuditEvent
}

func (s *testAuditSink) Log(event *AuditEvent) {
	*s.events = append(*s.events, event)
}
