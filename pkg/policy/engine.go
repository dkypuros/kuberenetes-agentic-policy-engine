package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// Engine evaluates tool requests against compiled policies.
// This is the core of the Agent Policy system - the equivalent of
// the SELinux security server.
//
// The engine supports two evaluation modes:
//   - Legacy: Uses ToolTable map lookup with inline constraint checking
//   - OPA: Uses prepared OPA queries for policy-as-code evaluation
//
// Usage:
//
//	engine := NewEngine(WithMode(Enforcing), WithOPA(true))
//	engine.LoadPolicy("coding-assistant", compiledPolicy)
//	decision, err := engine.Evaluate(ctx, agentCtx, "file.read", request)
type Engine struct {
	mu       sync.RWMutex
	policies map[string]*CompiledPolicy // agentType -> policy
	cache    *DecisionCache
	audit    AuditSink
	mode     EnforcementMode

	// OPA integration (Phase 2)
	useOPA  bool          // Feature flag for OPA evaluation
	opaEval *OPAEvaluator // OPA evaluator instance (nil if not using OPA)
}

// AuditSink is the interface for audit event consumers
type AuditSink interface {
	Log(event *AuditEvent)
}

// Option configures the Engine
type Option func(*Engine)

// WithMode sets the enforcement mode
func WithMode(mode EnforcementMode) Option {
	return func(e *Engine) {
		e.mode = mode
	}
}

// WithCache sets a custom cache (for testing)
func WithCache(cache *DecisionCache) Option {
	return func(e *Engine) {
		e.cache = cache
	}
}

// WithAuditSink sets the audit event sink
func WithAuditSink(sink AuditSink) Option {
	return func(e *Engine) {
		e.audit = sink
	}
}

// WithOPA enables OPA-based policy evaluation.
// When enabled, policies with OPAEnabled=true and a PreparedQuery
// will be evaluated using OPA instead of the legacy ToolTable engine.
//
// This allows gradual migration from the legacy engine to OPA:
//   - useOPA=false: All policies use legacy ToolTable evaluation
//   - useOPA=true: Policies with OPAEnabled=true use OPA, others use legacy
func WithOPA(enabled bool) Option {
	return func(e *Engine) {
		e.useOPA = enabled
		if enabled {
			e.opaEval = NewOPAEvaluator(e.cache, e.audit, e.mode)
		}
	}
}

// NewEngine creates a new policy engine.
// Default: Permissive mode, 60-second cache TTL
func NewEngine(opts ...Option) *Engine {
	e := &Engine{
		policies: make(map[string]*CompiledPolicy),
		cache:    NewDecisionCache(60 * time.Second),
		mode:     Permissive, // Safe default - log only
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Evaluate checks if an agent can call a tool.
// This is the hot path - optimized for speed.
//
// The evaluation mode is determined by:
//  1. Engine's useOPA flag (global feature flag)
//  2. Policy's OPAEnabled flag (per-policy opt-in)
//  3. Presence of PreparedQuery in the policy
//
// Returns:
//   - Allow: agent may proceed with tool call
//   - Deny: agent must not call tool (in Enforcing mode)
//
// In Permissive mode, Deny decisions are logged but Allow is returned.
func (e *Engine) Evaluate(ctx context.Context, agent AgentContext, toolName string, request interface{}) (Decision, error) {
	requestID := generateRequestID()

	// 1. Check cache first (microsecond path)
	cacheKey := CacheKey(agent.AgentType, toolName)
	if decision, reason, ok := e.cache.Get(cacheKey); ok {
		e.emitAudit(agent, toolName, decision, reason, requestID, true)
		return e.applyMode(decision), nil
	}

	// 2. Look up policy for this agent type
	e.mu.RLock()
	policy, exists := e.policies[agent.AgentType]
	e.mu.RUnlock()

	if !exists {
		// No policy defined for this agent type
		decision := Deny
		reason := "no policy defined for agent type"
		e.cache.Set(cacheKey, decision, reason)
		e.emitAudit(agent, toolName, decision, reason, requestID, false)
		return e.applyMode(decision), nil
	}

	// 3. Evaluate using OPA or legacy engine
	var decision Decision
	var reason string

	if e.shouldUseOPA(policy) {
		// OPA evaluation path (~100-500μs)
		decision, reason = e.evaluateOPA(ctx, policy, agent, toolName, request)
	} else {
		// Legacy evaluation path (~10-100μs)
		decision, reason = e.evaluatePolicy(policy, toolName, request)
	}

	// 4. Cache the decision
	e.cache.Set(cacheKey, decision, reason)

	// 5. Emit audit event
	e.emitAudit(agent, toolName, decision, reason, requestID, false)

	// 6. Apply enforcement mode
	return e.applyMode(decision), nil
}

// shouldUseOPA determines if OPA should be used for this policy.
func (e *Engine) shouldUseOPA(policy *CompiledPolicy) bool {
	return e.useOPA && policy.OPAEnabled && policy.PreparedQuery != nil
}

// evaluateOPA runs the prepared OPA query for policy evaluation.
// This is the OPA hot path - uses pre-compiled queries for speed.
func (e *Engine) evaluateOPA(ctx context.Context, policy *CompiledPolicy, agent AgentContext, toolName string, request interface{}) (Decision, string) {
	// Convert request to map if needed
	params, ok := request.(map[string]interface{})
	if !ok {
		params = make(map[string]interface{})
	}

	// Use the OPA evaluator if available
	if e.opaEval != nil {
		decision, reason, err := e.opaEval.Evaluate(ctx, agent, toolName, params)
		if err != nil {
			// OPA error - fail closed
			return Deny, fmt.Sprintf("OPA evaluation error: %v", err)
		}
		return decision, reason
	}

	// Fallback: OPA evaluator not initialized
	// This should not happen in normal operation as the evaluator is created with the engine
	return Deny, "OPA evaluator not initialized"
}

// evaluatePolicy checks the policy for a specific tool
func (e *Engine) evaluatePolicy(policy *CompiledPolicy, toolName string, request interface{}) (Decision, string) {
	// Check explicit tool permission
	if perm, ok := policy.ToolTable[toolName]; ok {
		if perm.Action == Deny {
			return Deny, "tool explicitly denied by policy"
		}

		// Tool allowed - check constraints if any
		if perm.Constraints != nil {
			if !e.checkConstraints(perm.Constraints, toolName, request) {
				return Deny, "constraint violation"
			}
		}
		return Allow, "tool explicitly allowed by policy"
	}

	// Tool not in policy - use default action
	if policy.DefaultAction == Allow {
		return Allow, "allowed by default policy"
	}
	return Deny, "denied by default policy"
}

// checkConstraints evaluates constraint rules against the request
func (e *Engine) checkConstraints(constraints *ToolConstraints, toolName string, request interface{}) bool {
	// Type-assert request to extract parameters
	// In production, this would be the proto.ExecuteRequest
	params, ok := request.(map[string]interface{})
	if !ok {
		// Can't check constraints without structured request
		return true
	}

	// Check path constraints for file operations
	if len(constraints.PathPatterns) > 0 {
		if path, ok := params["path"].(string); ok {
			matched := false
			for _, pattern := range constraints.PathPatterns {
				if match, _ := filepath.Match(pattern, path); match {
					matched = true
					break
				}
				// Also check if path is under pattern directory
				if matchPrefix(pattern, path) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Check domain constraints for network operations
	if len(constraints.AllowedDomains) > 0 {
		if domain, ok := params["domain"].(string); ok {
			allowed := false
			for _, d := range constraints.AllowedDomains {
				if matchDomain(d, domain) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
	}

	// Check denied domains
	if len(constraints.DeniedDomains) > 0 {
		if domain, ok := params["domain"].(string); ok {
			for _, d := range constraints.DeniedDomains {
				if matchDomain(d, domain) {
					return false
				}
			}
		}
	}

	// Check size constraints
	if constraints.MaxSizeBytes > 0 {
		if size, ok := params["size"].(int64); ok {
			if size > constraints.MaxSizeBytes {
				return false
			}
		}
	}

	return true
}

// applyMode returns the final decision based on enforcement mode
func (e *Engine) applyMode(decision Decision) Decision {
	if e.mode == Permissive && decision == Deny {
		// In permissive mode, log but allow
		return Allow
	}
	return decision
}

// emitAudit sends an audit event to the sink
func (e *Engine) emitAudit(agent AgentContext, tool string, decision Decision, reason, requestID string, cached bool) {
	if e.audit == nil {
		return
	}

	e.audit.Log(&AuditEvent{
		Timestamp: time.Now(),
		Agent:     agent,
		Tool:      tool,
		Decision:  decision,
		Reason:    reason,
		RequestID: requestID,
		Cached:    cached,
	})
}

// LoadPolicy adds or updates a policy for an agent type.
// This invalidates cached decisions for that agent type.
func (e *Engine) LoadPolicy(agentType string, policy *CompiledPolicy) {
	e.mu.Lock()
	e.policies[agentType] = policy
	e.mu.Unlock()

	// Invalidate cache entries for this agent type
	e.cache.InvalidatePrefix(agentType + ":")
}

// RemovePolicy removes a policy for an agent type.
func (e *Engine) RemovePolicy(agentType string) {
	e.mu.Lock()
	delete(e.policies, agentType)
	e.mu.Unlock()

	e.cache.InvalidatePrefix(agentType + ":")
}

// GetPolicy returns the policy for an agent type (for inspection).
func (e *Engine) GetPolicy(agentType string) (*CompiledPolicy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	policy, ok := e.policies[agentType]
	return policy, ok
}

// ListPolicies returns all loaded agent types.
func (e *Engine) ListPolicies() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	types := make([]string, 0, len(e.policies))
	for t := range e.policies {
		types = append(types, t)
	}
	return types
}

// Mode returns the current enforcement mode.
func (e *Engine) Mode() EnforcementMode {
	return e.mode
}

// SetMode changes the enforcement mode.
func (e *Engine) SetMode(mode EnforcementMode) {
	e.mode = mode
}

// CacheStats returns cache statistics.
func (e *Engine) CacheStats() (hits, misses uint64, hitRate float64) {
	return e.cache.Stats()
}

// IsOPAEnabled returns whether OPA evaluation is enabled.
func (e *Engine) IsOPAEnabled() bool {
	return e.useOPA
}

// OPAEvaluator returns the OPA evaluator instance (for testing/inspection).
func (e *Engine) OPAEvaluator() *OPAEvaluator {
	return e.opaEval
}

// Cache returns the decision cache (for testing/inspection).
func (e *Engine) Cache() *DecisionCache {
	return e.cache
}

// --- Helper functions ---

// matchPrefix checks if path starts with pattern (for directory patterns like /workspace/**)
func matchPrefix(pattern, path string) bool {
	// Handle ** patterns
	if len(pattern) > 2 && pattern[len(pattern)-2:] == "**" {
		prefix := pattern[:len(pattern)-2]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}

// matchDomain checks if domain matches pattern (supports wildcards)
func matchDomain(pattern, domain string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 1 && pattern[0] == '*' && pattern[1] == '.' {
		// *.example.com matches foo.example.com
		suffix := pattern[1:] // .example.com
		return len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix
	}
	return pattern == domain
}

// generateRequestID creates a unique request identifier
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// --- Policy Compilation ---

// CompilePolicy converts raw policy spec to optimized CompiledPolicy.
// This creates a legacy-mode policy (OPAEnabled=false).
// Use CompilePolicyWithOPA for OPA-enabled policies.
func CompilePolicy(name string, agentTypes []string, defaultAction Decision, permissions []ToolPermission, mode EnforcementMode, mtsLabel string) *CompiledPolicy {
	toolTable := make(map[string]*ToolPermission, len(permissions))
	for i := range permissions {
		toolTable[permissions[i].Tool] = &permissions[i]
	}

	return &CompiledPolicy{
		Name:          name,
		AgentTypes:    agentTypes,
		DefaultAction: defaultAction,
		ToolTable:     toolTable,
		Mode:          mode,
		MTSLabel:      mtsLabel,
		CompiledAt:    time.Now(),
		// OPA fields default to disabled
		OPAEnabled:    false,
		RegoModule:    "",
		PreparedQuery: nil,
	}
}

// CompilePolicyWithOPA creates an OPA-enabled CompiledPolicy.
// The regoModule is compiled using PrepareRegoQuery and cached
// for fast evaluation on subsequent requests.
func CompilePolicyWithOPA(name string, agentTypes []string, defaultAction Decision, permissions []ToolPermission, mode EnforcementMode, mtsLabel string, regoModule string) (*CompiledPolicy, error) {
	// Create base policy with legacy support
	policy := CompilePolicy(name, agentTypes, defaultAction, permissions, mode, mtsLabel)

	// Add OPA support
	policy.RegoModule = regoModule
	policy.OPAEnabled = true

	// Prepare the OPA query (expensive: ~50ms, but done once)
	prepared, err := PrepareRegoQuery(regoModule)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Rego module: %w", err)
	}
	policy.PreparedQuery = &prepared

	return policy, nil
}
