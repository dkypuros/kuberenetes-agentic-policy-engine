// Package router provides the integration layer between the Agent Sandbox Router
// and the Policy Engine. This is where Mandatory Access Control is enforced.
//
// The router is the "syscall interface" of the agentic kernel - every tool call
// passes through it. This package implements the LSM hook pattern: intercept
// requests at the boundary, evaluate against policy, and enforce decisions.
//
// Architecture:
//
//	Agent -> Router -> PolicyIntegration -> PolicyEngine
//	                         |                   |
//	                         v                   v
//	                   extractIdentity     Evaluate()
//	                         |                   |
//	                         v                   v
//	                   AgentContext         Decision
//
// The integration is designed to add minimal latency (<1ms) to the request path.
package router

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	agentsv1alpha1 "github.com/golden-agent/golden-agent/api/v1alpha1"
	"github.com/golden-agent/golden-agent/pkg/controller"
	"github.com/golden-agent/golden-agent/pkg/policy"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(agentsv1alpha1.AddToScheme(scheme))
}

// PolicyConfig holds configuration for the router's policy integration.
type PolicyConfig struct {
	// Mode is the enforcement mode (Permissive or Enforcing)
	Mode policy.EnforcementMode

	// CacheTTL is the duration to cache policy decisions
	CacheTTL time.Duration

	// PolicyPath is the path to watch for AgentPolicy CRDs (Kubernetes mode)
	PolicyPath string

	// AuditEnabled enables audit event emission
	AuditEnabled bool

	// AuditSink is the destination for audit events (optional)
	AuditSink policy.AuditSink

	// ============================================================
	// OPA Integration Settings
	// ============================================================

	// UseOPA enables OPA-based policy evaluation.
	// When true, policies are compiled to Rego and use OPA's prepared queries.
	// When false, policies use the legacy ToolTable evaluation.
	UseOPA bool

	// EnableController enables the Kubernetes controller for CRD watching.
	// When true, the router will watch for AgentPolicy CRDs and sync them.
	EnableController bool

	// MetricsAddr is the address for the controller metrics endpoint.
	// Default: ":8080"
	MetricsAddr string

	// HealthProbeAddr is the address for the controller health probes.
	// Default: ":8081"
	HealthProbeAddr string
}

// DefaultPolicyConfig returns sensible defaults for policy integration.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		Mode:             policy.Permissive, // Safe default: log only
		CacheTTL:         60 * time.Second,
		AuditEnabled:     true,
		UseOPA:           false,            // OPA disabled by default for safe rollout
		EnableController: false,            // Controller disabled by default
		MetricsAddr:      ":8080",
		HealthProbeAddr:  ":8081",
	}
}

// DefaultPolicyConfigWithOPA returns defaults with OPA enabled.
func DefaultPolicyConfigWithOPA() PolicyConfig {
	config := DefaultPolicyConfig()
	config.UseOPA = true
	config.EnableController = true
	return config
}

// RouterPolicyIntegration connects the router to the policy engine.
// This is the main integration point - it holds the engine and provides
// methods for the router to call before executing tool requests.
//
// When OPA is enabled, policies are evaluated using prepared OPA queries.
// When the controller is enabled, policies are synced from Kubernetes CRDs.
type RouterPolicyIntegration struct {
	engine *policy.Engine
	config PolicyConfig

	// mu protects watcher state
	mu       sync.RWMutex
	watching bool
	stopCh   chan struct{}

	// Controller-runtime manager (nil if controller not enabled)
	mgr ctrl.Manager
}

// NewRouterPolicyIntegration creates a new policy integration layer.
func NewRouterPolicyIntegration(config PolicyConfig) *RouterPolicyIntegration {
	return &RouterPolicyIntegration{
		engine: initPolicyEngine(config),
		config: config,
	}
}

// initPolicyEngine creates and configures the policy engine.
func initPolicyEngine(config PolicyConfig) *policy.Engine {
	opts := []policy.Option{
		policy.WithMode(config.Mode),
	}

	if config.CacheTTL > 0 {
		opts = append(opts, policy.WithCache(policy.NewDecisionCache(config.CacheTTL)))
	}

	if config.AuditSink != nil {
		opts = append(opts, policy.WithAuditSink(config.AuditSink))
	}

	// Enable OPA if configured
	if config.UseOPA {
		opts = append(opts, policy.WithOPA(true))
	}

	return policy.NewEngine(opts...)
}

// RequestMetadata contains identity and context from the gRPC request.
// In production, this maps to fields from the ExecuteRequest proto.
type RequestMetadata struct {
	// AgentType is the type/class of agent (e.g., "coding-assistant")
	AgentType string

	// SandboxID is the unique identifier of the sandbox
	SandboxID string

	// TenantID is the tenant/organization identifier
	TenantID string

	// SessionID is the current session identifier
	SessionID string

	// MTSLabel is the Multi-Tenant Sandboxing label
	MTSLabel string

	// PolicyRef is the name of the policy to apply (optional override)
	PolicyRef string
}

// extractAgentIdentity builds an AgentContext from request metadata.
// This is called for every tool request to establish the caller's identity.
func extractAgentIdentity(metadata RequestMetadata) policy.AgentContext {
	return policy.AgentContext{
		AgentType: metadata.AgentType,
		SandboxID: metadata.SandboxID,
		TenantID:  metadata.TenantID,
		SessionID: metadata.SessionID,
		MTSLabel:  metadata.MTSLabel,
		PolicyRef: metadata.PolicyRef,
	}
}

// extractToolName parses the tool name from a request.
// Tool names follow the pattern: "category.action" (e.g., "file.read", "code.exec").
//
// The function normalizes various input formats:
//   - "file.read" -> "file.read"
//   - "FileRead" -> "file.read"
//   - "file_read" -> "file.read"
func extractToolName(rawName string) string {
	if rawName == "" {
		return ""
	}

	// Already in correct format
	if strings.Contains(rawName, ".") {
		return strings.ToLower(rawName)
	}

	// Convert CamelCase to dot notation
	// FileRead -> file.read
	var result strings.Builder
	for i, r := range rawName {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('.')
		}
		result.WriteRune(r)
	}

	// Convert snake_case to dot notation
	normalized := strings.ToLower(result.String())
	return strings.ReplaceAll(normalized, "_", ".")
}

// Evaluate checks if a tool request is permitted.
// This is the main entry point called by the router for every tool call.
//
// Returns:
//   - (Allow, nil): Proceed with tool execution
//   - (Deny, nil): Block the request (in Enforcing mode)
//   - (_, error): Internal error during evaluation
func (r *RouterPolicyIntegration) Evaluate(
	ctx context.Context,
	metadata RequestMetadata,
	toolName string,
	request interface{},
) (policy.Decision, error) {
	// Extract identity from metadata
	agentCtx := extractAgentIdentity(metadata)

	// Normalize tool name
	normalizedTool := extractToolName(toolName)
	if normalizedTool == "" {
		return policy.Deny, errors.New("empty tool name")
	}

	// Delegate to policy engine
	return r.engine.Evaluate(ctx, agentCtx, normalizedTool, request)
}

// LoadPolicy adds or updates a policy for an agent type.
// Called when AgentPolicy CRDs are created or updated.
func (r *RouterPolicyIntegration) LoadPolicy(agentType string, compiled *policy.CompiledPolicy) {
	r.engine.LoadPolicy(agentType, compiled)
}

// RemovePolicy removes a policy for an agent type.
// Called when AgentPolicy CRDs are deleted.
func (r *RouterPolicyIntegration) RemovePolicy(agentType string) {
	r.engine.RemovePolicy(agentType)
}

// StartController starts the Kubernetes controller for watching AgentPolicy CRDs.
// This creates a controller-runtime manager and registers the AgentPolicyReconciler.
//
// The controller runs in a background goroutine and syncs policies from
// Kubernetes to the embedded policy engine.
//
// Call StopWatching() to gracefully shutdown the controller.
func (r *RouterPolicyIntegration) StartController(ctx context.Context) error {
	if !r.config.EnableController {
		return errors.New("controller not enabled in config")
	}

	r.mu.Lock()
	if r.watching {
		r.mu.Unlock()
		return errors.New("controller already running")
	}
	r.watching = true
	r.stopCh = make(chan struct{})
	r.mu.Unlock()

	// Setup logging
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	// Create controller-runtime manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false, // Embedded controller, no leader election
	})
	if err != nil {
		r.mu.Lock()
		r.watching = false
		r.mu.Unlock()
		return fmt.Errorf("failed to create manager: %w", err)
	}

	r.mgr = mgr

	// Register AgentPolicy controller
	reconciler := &controller.AgentPolicyReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		PolicyEngine: r.engine,
		UseOPA:       r.config.UseOPA,
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		r.mu.Lock()
		r.watching = false
		r.mu.Unlock()
		return fmt.Errorf("failed to setup controller: %w", err)
	}

	// Start manager in background goroutine
	go func() {
		if err := mgr.Start(ctx); err != nil {
			// Log error but don't crash - the router can still function
			// with pre-loaded policies
			fmt.Printf("controller manager error: %v\n", err)
		}

		r.mu.Lock()
		r.watching = false
		r.mu.Unlock()
	}()

	return nil
}

// watchPolicies is the legacy method for starting the policy watcher.
// Deprecated: Use StartController instead.
func (r *RouterPolicyIntegration) watchPolicies(ctx context.Context) error {
	return r.StartController(ctx)
}

// StopWatching stops the policy watcher.
func (r *RouterPolicyIntegration) StopWatching() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.watching && r.stopCh != nil {
		close(r.stopCh)
		r.watching = false
	}
}

// Engine returns the underlying policy engine (for testing and inspection).
func (r *RouterPolicyIntegration) Engine() *policy.Engine {
	return r.engine
}

// Mode returns the current enforcement mode.
func (r *RouterPolicyIntegration) Mode() policy.EnforcementMode {
	return r.engine.Mode()
}

// SetMode changes the enforcement mode at runtime.
// This allows operators to switch between Permissive and Enforcing without restart.
func (r *RouterPolicyIntegration) SetMode(mode policy.EnforcementMode) {
	r.engine.SetMode(mode)
}

// Stats returns policy engine statistics.
func (r *RouterPolicyIntegration) Stats() (cacheHits, cacheMisses uint64, hitRate float64, loadedPolicies int) {
	cacheHits, cacheMisses, hitRate = r.engine.CacheStats()
	loadedPolicies = len(r.engine.ListPolicies())
	return
}

// HealthCheck verifies the policy integration is operational.
func (r *RouterPolicyIntegration) HealthCheck() error {
	if r.engine == nil {
		return errors.New("policy engine not initialized")
	}
	return nil
}

// String returns a string representation for logging.
func (r *RouterPolicyIntegration) String() string {
	policies := r.engine.ListPolicies()
	return fmt.Sprintf("RouterPolicyIntegration{mode=%s, policies=%d, watching=%v, opa=%v}",
		r.engine.Mode(), len(policies), r.watching, r.config.UseOPA)
}

// IsOPAEnabled returns whether OPA evaluation is enabled.
func (r *RouterPolicyIntegration) IsOPAEnabled() bool {
	return r.config.UseOPA && r.engine.IsOPAEnabled()
}

// IsControllerRunning returns whether the Kubernetes controller is running.
func (r *RouterPolicyIntegration) IsControllerRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.watching
}
