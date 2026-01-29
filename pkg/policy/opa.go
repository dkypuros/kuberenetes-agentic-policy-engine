// Package policy provides the OPA integration for the Golden Agent policy engine.
// This file implements embedded OPA evaluation using prepared queries for
// sub-millisecond latency on the hot path.
//
// Architecture:
//
//	AgentPolicy CRD -> Rego Module -> PreparedEvalQuery -> Fast Evaluation
//	                   (compile once)  (reuse many times)
//
// The OPA evaluator is designed to be embedded in the router binary,
// not as a sidecar, ensuring complete mediation of all tool calls.
package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

// OPAPolicy represents a compiled OPA policy ready for high-speed evaluation.
// The PreparedQuery is compiled once when the policy is loaded and reused
// for every evaluation, avoiding the ~50ms compilation cost on each request.
type OPAPolicy struct {
	// Name is the policy identifier (from AgentPolicy CRD metadata.name)
	Name string

	// AgentTypes are the agent types this policy applies to
	AgentTypes []string

	// PreparedQuery is the pre-compiled OPA query for fast evaluation
	// This is the key to achieving <500μs evaluation latency
	PreparedQuery rego.PreparedEvalQuery

	// RegoModule is the generated Rego source code (for debugging/audit)
	RegoModule string

	// MTSLabel is the Multi-Tenant Sandboxing label for tenant isolation
	MTSLabel string

	// Mode is the enforcement mode (Permissive or Enforcing)
	Mode EnforcementMode

	// CompiledAt is when this policy was compiled
	CompiledAt time.Time
}

// OPAEvaluator wraps OPA's rego package for embedded, low-latency evaluation.
// It maintains a map of prepared queries per agent type and integrates with
// the existing DecisionCache for sub-microsecond cache hits.
type OPAEvaluator struct {
	mu       sync.RWMutex
	policies map[string]*OPAPolicy // agentType -> compiled policy

	// cache is the shared decision cache (AVC pattern)
	// OPA evaluation results are cached here for repeated queries
	cache *DecisionCache

	// audit receives all policy decisions for compliance logging
	audit AuditSink

	// mode is the global enforcement mode
	mode EnforcementMode
}

// OPAInput is the structured input passed to OPA for policy evaluation.
// This structure is serialized to JSON and becomes `input` in Rego.
type OPAInput struct {
	// Tool is the tool being requested (e.g., "file.read", "network.fetch")
	Tool string `json:"tool"`

	// Request contains tool-specific parameters
	Request map[string]interface{} `json:"request"`

	// Agent contains the requesting agent's identity
	Agent OPAAgentInput `json:"agent"`

	// Policy contains the policy metadata for MTS checks
	Policy OPAPolicyInput `json:"policy"`
}

// OPAAgentInput represents the agent identity in OPA input.
type OPAAgentInput struct {
	Type      string `json:"type"`
	SandboxID string `json:"sandbox_id"`
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"session_id"`
	MTSLabel  string `json:"mts_label"`
}

// OPAPolicyInput represents policy metadata in OPA input.
type OPAPolicyInput struct {
	Name     string `json:"name"`
	MTSLabel string `json:"mts_label"`
}

// OPAOutput is the expected output structure from OPA evaluation.
// The Rego policy must return a decision object matching this structure.
type OPAOutput struct {
	Allow  bool   `json:"allow"`
	Deny   bool   `json:"deny"`
	MTS    bool   `json:"mts"`
	Reason string `json:"reason"`
}

// NewOPAEvaluator creates a new OPA evaluator with the given options.
func NewOPAEvaluator(cache *DecisionCache, audit AuditSink, mode EnforcementMode) *OPAEvaluator {
	return &OPAEvaluator{
		policies: make(map[string]*OPAPolicy),
		cache:    cache,
		audit:    audit,
		mode:     mode,
	}
}

// Evaluate checks if the given agent can call the specified tool.
// This is the hot path - optimized for speed using prepared queries.
//
// Performance targets:
//   - Cache hit: <1μs (handled by caller's DecisionCache)
//   - Cache miss: <500μs (OPA PreparedEvalQuery.Eval)
//
// Returns:
//   - (Allow, nil): Agent may proceed with tool call
//   - (Deny, nil): Agent must not call tool
//   - (_, error): Evaluation error (fail closed)
func (e *OPAEvaluator) Evaluate(ctx context.Context, agent AgentContext, toolName string, request map[string]interface{}) (Decision, string, error) {
	// Look up policy for agent type
	e.mu.RLock()
	policy, exists := e.policies[agent.AgentType]
	e.mu.RUnlock()

	if !exists {
		return Deny, "no OPA policy defined for agent type", nil
	}

	// Build OPA input
	input := OPAInput{
		Tool:    toolName,
		Request: request,
		Agent: OPAAgentInput{
			Type:      agent.AgentType,
			SandboxID: agent.SandboxID,
			TenantID:  agent.TenantID,
			SessionID: agent.SessionID,
			MTSLabel:  agent.MTSLabel,
		},
		Policy: OPAPolicyInput{
			Name:     policy.Name,
			MTSLabel: policy.MTSLabel,
		},
	}

	// Evaluate using prepared query (fast path: ~100-500μs)
	results, err := policy.PreparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Deny, fmt.Sprintf("OPA evaluation error: %v", err), err
	}

	if len(results) == 0 {
		return Deny, "OPA returned no results", nil
	}

	// Extract decision from OPA result
	return e.extractDecision(results[0])
}

// extractDecision parses the OPA evaluation result into a Decision.
func (e *OPAEvaluator) extractDecision(result rego.Result) (Decision, string, error) {
	// OPA returns results as []rego.Result where each Result has Expressions
	if len(result.Expressions) == 0 {
		return Deny, "no expressions in OPA result", nil
	}

	// The first expression should be our decision object
	value := result.Expressions[0].Value

	// Try to extract as map (OPA returns interface{})
	decision, ok := value.(map[string]interface{})
	if !ok {
		// If it's a simple boolean (from data.policy.allow query)
		if allowed, ok := value.(bool); ok {
			if allowed {
				return Allow, "allowed by OPA policy", nil
			}
			return Deny, "denied by OPA policy", nil
		}
		return Deny, "unexpected OPA result type", nil
	}

	// Extract fields from decision object
	reason := "policy decision"
	if r, ok := decision["reason"].(string); ok {
		reason = r
	}

	// Check MTS first (tenant isolation takes precedence)
	if mts, ok := decision["mts"].(bool); ok && !mts {
		return Deny, "MTS violation: " + reason, nil
	}

	// Check explicit deny
	if denied, ok := decision["deny"].(bool); ok && denied {
		return Deny, reason, nil
	}

	// Check allow
	if allowed, ok := decision["allow"].(bool); ok && allowed {
		return Allow, reason, nil
	}

	// Default deny (fail closed)
	return Deny, "denied by default: " + reason, nil
}

// LoadPolicy compiles a Rego module and stores it for the given agent types.
// This is called when AgentPolicy CRDs are created or updated.
//
// The compilation is expensive (~50ms) but happens only once per policy update.
// Subsequent evaluations use the PreparedEvalQuery for fast evaluation.
func (e *OPAEvaluator) LoadPolicy(name string, agentTypes []string, regoModule string, mtsLabel string, mode EnforcementMode) error {
	// Prepare the query (expensive: ~50ms)
	prepared, err := PrepareRegoQuery(regoModule)
	if err != nil {
		return fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	policy := &OPAPolicy{
		Name:          name,
		AgentTypes:    agentTypes,
		PreparedQuery: prepared,
		RegoModule:    regoModule,
		MTSLabel:      mtsLabel,
		Mode:          mode,
		CompiledAt:    time.Now(),
	}

	// Register for each agent type
	e.mu.Lock()
	for _, agentType := range agentTypes {
		e.policies[agentType] = policy
	}
	e.mu.Unlock()

	// Invalidate cache for affected agent types
	if e.cache != nil {
		for _, agentType := range agentTypes {
			e.cache.InvalidatePrefix(agentType + ":")
		}
	}

	return nil
}

// RemovePolicy removes a policy for the given agent type.
// Called when AgentPolicy CRDs are deleted.
func (e *OPAEvaluator) RemovePolicy(agentType string) {
	e.mu.Lock()
	delete(e.policies, agentType)
	e.mu.Unlock()

	if e.cache != nil {
		e.cache.InvalidatePrefix(agentType + ":")
	}
}

// GetPolicy returns the policy for an agent type (for inspection/debugging).
func (e *OPAEvaluator) GetPolicy(agentType string) (*OPAPolicy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	policy, ok := e.policies[agentType]
	return policy, ok
}

// ListPolicies returns all loaded agent types.
func (e *OPAEvaluator) ListPolicies() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	types := make([]string, 0, len(e.policies))
	for t := range e.policies {
		types = append(types, t)
	}
	return types
}

// PrepareRegoQuery compiles a Rego module into a PreparedEvalQuery.
// This is the expensive operation (~50ms) that should be done once per policy.
//
// The query path "data.agentpolicy.decision" expects the Rego module to define:
//
//	package agentpolicy
//	decision := {"allow": bool, "deny": bool, "mts": bool, "reason": string}
func PrepareRegoQuery(regoModule string) (rego.PreparedEvalQuery, error) {
	// Create Rego instance with the module
	r := rego.New(
		rego.Query("data.agentpolicy.decision"),
		rego.Module("policy.rego", regoModule),
	)

	// Prepare for evaluation (compile to bytecode)
	ctx := context.Background()
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("failed to prepare Rego query: %w", err)
	}

	return prepared, nil
}

// ValidateRegoModule checks if a Rego module is syntactically valid.
// This is useful for validating policies before loading them.
func ValidateRegoModule(regoModule string) error {
	r := rego.New(
		rego.Query("data.agentpolicy.decision"),
		rego.Module("policy.rego", regoModule),
	)

	ctx := context.Background()
	_, err := r.PrepareForEval(ctx)
	return err
}
