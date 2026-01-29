// Package policy implements Mandatory Access Control for AI agent tool invocations.
// This is the SELinux pattern applied to the agentic kernel.
package policy

import (
	"time"

	"github.com/open-policy-agent/opa/rego"
)

// Decision represents the outcome of a policy evaluation
type Decision int

const (
	// Deny blocks the tool call
	Deny Decision = iota
	// Allow permits the tool call
	Allow
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "ALLOW"
	case Deny:
		return "DENY"
	default:
		return "UNKNOWN"
	}
}

// EnforcementMode controls how policy decisions are applied
type EnforcementMode int

const (
	// Permissive logs denials but allows all requests (for testing/rollout)
	Permissive EnforcementMode = iota
	// Enforcing actually blocks denied requests
	Enforcing
)

func (m EnforcementMode) String() string {
	switch m {
	case Permissive:
		return "permissive"
	case Enforcing:
		return "enforcing"
	default:
		return "unknown"
	}
}

// ToolPermission defines access rules for a specific tool
type ToolPermission struct {
	// Tool is the name of the tool (e.g., "file.read", "network.fetch")
	Tool string

	// Action is the decision for this tool (Allow or Deny)
	Action Decision

	// Constraints are optional conditions for the permission
	Constraints *ToolConstraints
}

// ToolConstraints define conditional access rules
type ToolConstraints struct {
	// PathPatterns for file operations (glob patterns)
	PathPatterns []string

	// AllowedDomains for network operations
	AllowedDomains []string

	// DeniedDomains explicitly blocked domains
	DeniedDomains []string

	// AllowedPorts for network operations
	AllowedPorts []int

	// MaxSizeBytes for write operations
	MaxSizeBytes int64

	// Timeout for execution operations
	Timeout time.Duration
}

// CompiledPolicy is a pre-processed policy for fast evaluation.
// Supports both legacy (ToolTable lookup) and OPA (PreparedQuery) evaluation.
type CompiledPolicy struct {
	// Name of the policy (from CRD metadata)
	Name string

	// AgentTypes this policy applies to
	AgentTypes []string

	// DefaultAction for tools not explicitly listed
	DefaultAction Decision

	// ToolTable maps tool names to permissions for O(1) lookup (legacy engine)
	ToolTable map[string]*ToolPermission

	// Mode is the enforcement mode
	Mode EnforcementMode

	// MTSLabel for multi-tenant isolation
	MTSLabel string

	// CompiledAt is when this policy was compiled
	CompiledAt time.Time

	// ============================================================
	// OPA Integration Fields (Phase 2)
	// ============================================================

	// RegoModule is the generated Rego source code (for debugging/audit)
	RegoModule string

	// PreparedQuery is the pre-compiled OPA query for fast evaluation.
	// This is nil when using the legacy engine.
	PreparedQuery *rego.PreparedEvalQuery

	// OPAEnabled indicates whether to use OPA for this policy.
	// When true and PreparedQuery is set, OPA evaluation is used.
	// When false, legacy ToolTable evaluation is used.
	OPAEnabled bool
}

// AgentContext represents the identity of an agent making a request
type AgentContext struct {
	// AgentType is the type/class of agent (e.g., "coding-assistant")
	AgentType string

	// SandboxID is the unique identifier of the sandbox
	SandboxID string

	// TenantID is the tenant/organization identifier
	TenantID string

	// SessionID is the session identifier
	SessionID string

	// MTSLabel is the Multi-Tenant Sandboxing label
	MTSLabel string

	// PolicyRef is the name of the policy being applied
	PolicyRef string
}

// AuditEvent records a policy decision for compliance
type AuditEvent struct {
	// Timestamp of the decision
	Timestamp time.Time

	// AgentContext is the identity making the request
	Agent AgentContext

	// Tool being called
	Tool string

	// Decision made (Allow or Deny)
	Decision Decision

	// Reason for the decision
	Reason string

	// RequestID for correlation
	RequestID string

	// Cached indicates if this was a cache hit
	Cached bool
}
