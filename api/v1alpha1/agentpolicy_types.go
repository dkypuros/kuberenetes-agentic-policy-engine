// Package v1alpha1 contains API Schema definitions for the agents.sandbox.io v1alpha1 API group.
// This implements Mandatory Access Control for AI agent tool invocations,
// following the SELinux pattern applied to the agentic kernel.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ============================================================================
// Tool Permission Types
// ============================================================================

// DecisionAction represents the outcome of a policy evaluation.
// +kubebuilder:validation:Enum=allow;deny
type DecisionAction string

const (
	// DecisionAllow permits the tool call.
	DecisionAllow DecisionAction = "allow"
	// DecisionDeny blocks the tool call.
	DecisionDeny DecisionAction = "deny"
)

// EnforcementMode controls how policy decisions are applied.
// +kubebuilder:validation:Enum=permissive;enforcing
type EnforcementMode string

const (
	// EnforcementModePermissive logs denials but allows all requests (for testing/rollout).
	EnforcementModePermissive EnforcementMode = "permissive"
	// EnforcementModeEnforcing actually blocks denied requests.
	EnforcementModeEnforcing EnforcementMode = "enforcing"
)

// MTSEnforceMode controls multi-tenant sandboxing strictness.
// +kubebuilder:validation:Enum=strict;permissive;disabled
type MTSEnforceMode string

const (
	// MTSEnforceModeStrict requires exact MTS label matches.
	MTSEnforceModeStrict MTSEnforceMode = "strict"
	// MTSEnforceModePermissive logs violations but allows cross-tenant access.
	MTSEnforceModePermissive MTSEnforceMode = "permissive"
	// MTSEnforceModeDisabled disables MTS checking.
	MTSEnforceModeDisabled MTSEnforceMode = "disabled"
)

// ToolConstraints define conditional access rules for tool permissions.
// These constraints mirror SELinux's fine-grained object class permissions.
type ToolConstraints struct {
	// PathPatterns are glob patterns for file operations.
	// Example: "/workspace/**", "/tmp/**"
	// +optional
	// +listType=atomic
	PathPatterns []string `json:"pathPatterns,omitempty"`

	// AllowedDomains are permitted domains for network operations.
	// Supports wildcards: "*.github.com"
	// +optional
	// +listType=atomic
	AllowedDomains []string `json:"allowedDomains,omitempty"`

	// DeniedDomains are explicitly blocked domains for network operations.
	// Takes precedence over AllowedDomains.
	// +optional
	// +listType=atomic
	DeniedDomains []string `json:"deniedDomains,omitempty"`

	// AllowedPorts are permitted ports for network operations.
	// Example: [80, 443]
	// +optional
	// +listType=atomic
	AllowedPorts []int32 `json:"allowedPorts,omitempty"`

	// MaxSizeBytes is the maximum size in bytes for write operations.
	// Example: 10485760 (10MB)
	// +optional
	// +kubebuilder:validation:Minimum=0
	MaxSizeBytes *int64 `json:"maxSizeBytes,omitempty"`

	// Timeout is the maximum execution time for operations.
	// Example: "60s", "5m"
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(s|m|h))+$`
	Timeout string `json:"timeout,omitempty"`
}

// ToolPermission defines access rules for a specific tool.
// This is analogous to SELinux type enforcement rules.
type ToolPermission struct {
	// Tool is the name of the tool being controlled.
	// Examples: "file.read", "file.write", "network.fetch", "code.execute"
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`
	Tool string `json:"tool"`

	// Action is the decision for this tool: allow or deny.
	// +kubebuilder:validation:Required
	Action DecisionAction `json:"action"`

	// Constraints are optional conditions that must be met for the permission.
	// Only applies when Action is "allow".
	// +optional
	Constraints *ToolConstraints `json:"constraints,omitempty"`
}

// ============================================================================
// Multi-Tenant Sandboxing (MTS) Configuration
// ============================================================================

// MTSConfig defines multi-tenant sandboxing settings.
// This is analogous to SELinux's Multi-Category Security (MCS).
type MTSConfig struct {
	// MTSLabel is the security label for tenant isolation.
	// Format follows SELinux MCS convention: "s0:c100,c200"
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^s[0-9]+(:c[0-9]+(,c[0-9]+)*)?$`
	MTSLabel string `json:"mtsLabel"`

	// EnforceMode controls how MTS violations are handled.
	// +kubebuilder:default=strict
	EnforceMode MTSEnforceMode `json:"enforceMode,omitempty"`
}

// ============================================================================
// Policy Reference (for SandboxClaim to reference policies)
// ============================================================================

// PolicyReference identifies an AgentPolicy resource.
type PolicyReference struct {
	// Name is the name of the AgentPolicy resource.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the namespace of the AgentPolicy resource.
	// If empty, defaults to the referencing resource's namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// ============================================================================
// AgentPolicy Spec and Status
// ============================================================================

// AgentPolicySpec defines the desired state of AgentPolicy.
// This is the declarative policy configuration that administrators create.
type AgentPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// AgentTypes is a list of agent types this policy applies to.
	// Example: ["coding-assistant", "code-reviewer"]
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	AgentTypes []string `json:"agentTypes"`

	// DefaultAction for tools not explicitly listed in ToolPermissions.
	// +kubebuilder:validation:Required
	// +kubebuilder:default=deny
	DefaultAction DecisionAction `json:"defaultAction"`

	// Mode is the enforcement mode for this policy.
	// "permissive" logs denials but allows all requests.
	// "enforcing" actually blocks denied requests.
	// +kubebuilder:default=enforcing
	Mode EnforcementMode `json:"mode,omitempty"`

	// ToolPermissions is the list of explicit tool permission rules.
	// Rules are evaluated in order; first match wins.
	// +optional
	// +listType=map
	// +listMapKey=tool
	ToolPermissions []ToolPermission `json:"toolPermissions,omitempty"`

	// TenantIsolation configures Multi-Tenant Sandboxing (MTS).
	// When set, cross-tenant access is controlled based on MTS labels.
	// +optional
	TenantIsolation *MTSConfig `json:"tenantIsolation,omitempty"`
}

// AgentPolicyStatus defines the observed state of AgentPolicy.
// This is updated by the controller to reflect the current state.
type AgentPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// CompiledHash is the hash of the compiled policy.
	// Used to detect when recompilation is needed.
	// +optional
	CompiledHash string `json:"compiledHash,omitempty"`

	// LastUpdated is the timestamp of the last policy compilation.
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// ActiveBindings is the count of SandboxClaims referencing this policy.
	// +optional
	// +kubebuilder:default=0
	ActiveBindings int32 `json:"activeBindings,omitempty"`

	// Conditions represent the latest available observations of the policy's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ============================================================================
// AgentPolicy Resource Definition
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ap;agpol
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.mode",description="Enforcement mode"
// +kubebuilder:printcolumn:name="Default",type="string",JSONPath=".spec.defaultAction",description="Default action"
// +kubebuilder:printcolumn:name="Bindings",type="integer",JSONPath=".status.activeBindings",description="Active sandbox bindings"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AgentPolicy is the Schema for the agentpolicies API.
// It defines Mandatory Access Control rules for AI agent tool invocations,
// following the SELinux pattern applied to the agentic kernel.
type AgentPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentPolicySpec   `json:"spec,omitempty"`
	Status AgentPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AgentPolicyList contains a list of AgentPolicy resources.
type AgentPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AgentPolicy{}, &AgentPolicyList{})
}
