// Package controller implements Kubernetes controllers for the Golden Agent.
// The AgentPolicyReconciler watches AgentPolicy CRDs and syncs them to the
// embedded policy engine, enabling declarative policy management.
//
// Architecture:
//
//	Kubernetes API ──watch──> AgentPolicyReconciler ──sync──> Policy Engine
//	     │                           │                            │
//	 AgentPolicy                 Reconcile()                 LoadPolicy()
//	    CRD                   (compile to Rego)           (PreparedQuery)
//
// The controller runs embedded in the router binary, not as a separate pod.
// This ensures policies are always in sync with the enforcement point.
package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	agentsv1alpha1 "github.com/golden-agent/golden-agent/api/v1alpha1"
	"github.com/golden-agent/golden-agent/pkg/policy"
	regotempl "github.com/golden-agent/golden-agent/pkg/policy/rego"
)

// AgentPolicyReconciler reconciles AgentPolicy objects.
// It watches for create/update/delete events and syncs policies
// to the embedded policy engine.
type AgentPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// PolicyEngine is the embedded policy engine to sync policies to.
	// This is the same engine used by the router for policy enforcement.
	PolicyEngine *policy.Engine

	// UseOPA enables OPA-based policy compilation.
	// When true, policies are compiled to Rego and use PreparedQuery.
	// When false, policies use legacy ToolTable evaluation.
	UseOPA bool
}

// Reconcile handles AgentPolicy create/update/delete events.
// This is called by controller-runtime when CRDs change.
//
// The reconciliation flow:
//  1. Fetch the AgentPolicy CRD
//  2. If deleted: remove policy from engine
//  3. Convert AgentPolicySpec to Rego (if OPA enabled)
//  4. Compile to CompiledPolicy
//  5. Load into engine for each agent type
//  6. Update CRD status
func (r *AgentPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the AgentPolicy
	var agentPolicy agentsv1alpha1.AgentPolicy
	if err := r.Get(ctx, req.NamespacedName, &agentPolicy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "unable to fetch AgentPolicy")
			return ctrl.Result{}, err
		}
		// Policy deleted - remove from engine
		r.handleDeletion(ctx, req.Name)
		return ctrl.Result{}, nil
	}

	log.Info("reconciling AgentPolicy", "name", agentPolicy.Name, "agentTypes", agentPolicy.Spec.AgentTypes)

	// Compile the policy
	compiled, regoModule, err := r.compilePolicy(&agentPolicy)
	if err != nil {
		log.Error(err, "failed to compile policy")
		r.updateStatus(ctx, &agentPolicy, "", err)
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	// Load into engine for each agent type
	for _, agentType := range agentPolicy.Spec.AgentTypes {
		r.PolicyEngine.LoadPolicy(agentType, compiled)
		log.Info("loaded policy", "agentType", agentType, "policy", agentPolicy.Name, "opaEnabled", compiled.OPAEnabled)
	}

	// Update status
	hash := computeHash(regoModule)
	if err := r.updateStatus(ctx, &agentPolicy, hash, nil); err != nil {
		log.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// handleDeletion removes a policy from the engine when the CRD is deleted.
// We don't know which agent types were affected, so we need to check
// all loaded policies and remove the ones matching this policy name.
func (r *AgentPolicyReconciler) handleDeletion(ctx context.Context, policyName string) {
	log := log.FromContext(ctx)

	// Remove policy for all agent types that had this policy
	for _, agentType := range r.PolicyEngine.ListPolicies() {
		if policy, ok := r.PolicyEngine.GetPolicy(agentType); ok {
			if policy.Name == policyName {
				r.PolicyEngine.RemovePolicy(agentType)
				log.Info("removed policy", "agentType", agentType, "policy", policyName)
			}
		}
	}
}

// compilePolicy converts an AgentPolicy CRD to a CompiledPolicy.
// Returns the compiled policy, the Rego module (if OPA enabled), and any error.
func (r *AgentPolicyReconciler) compilePolicy(ap *agentsv1alpha1.AgentPolicy) (*policy.CompiledPolicy, string, error) {
	// Convert CRD types to internal types
	defaultAction := policy.Deny
	if ap.Spec.DefaultAction == agentsv1alpha1.DecisionAllow {
		defaultAction = policy.Allow
	}

	mode := policy.Enforcing
	if ap.Spec.Mode == agentsv1alpha1.EnforcementModePermissive {
		mode = policy.Permissive
	}

	// Build tool permissions
	permissions := make([]policy.ToolPermission, 0, len(ap.Spec.ToolPermissions))
	for _, tp := range ap.Spec.ToolPermissions {
		action := policy.Deny
		if tp.Action == agentsv1alpha1.DecisionAllow {
			action = policy.Allow
		}

		perm := policy.ToolPermission{
			Tool:   tp.Tool,
			Action: action,
		}

		if tp.Constraints != nil {
			perm.Constraints = convertConstraints(tp.Constraints)
		}

		permissions = append(permissions, perm)
	}

	// Get MTS label
	mtsLabel := ""
	mtsEnforceMode := "strict"
	if ap.Spec.TenantIsolation != nil {
		mtsLabel = ap.Spec.TenantIsolation.MTSLabel
		if ap.Spec.TenantIsolation.EnforceMode != "" {
			mtsEnforceMode = string(ap.Spec.TenantIsolation.EnforceMode)
		}
	}

	// Compile with or without OPA
	if r.UseOPA {
		// Generate Rego module
		spec := &regotempl.PolicySpec{
			Name:           ap.Name,
			AgentTypes:     ap.Spec.AgentTypes,
			DefaultAction:  string(ap.Spec.DefaultAction),
			Mode:           string(ap.Spec.Mode),
			MTSLabel:       mtsLabel,
			MTSEnforceMode: mtsEnforceMode,
		}

		// Convert tool permissions to Rego spec
		for _, tp := range ap.Spec.ToolPermissions {
			tpSpec := regotempl.ToolPermissionSpec{
				Tool:   tp.Tool,
				Action: string(tp.Action),
			}

			if tp.Constraints != nil {
				tpSpec.Constraints = &regotempl.ConstraintSpec{
					PathPatterns:   tp.Constraints.PathPatterns,
					AllowedDomains: tp.Constraints.AllowedDomains,
					DeniedDomains:  tp.Constraints.DeniedDomains,
					AllowedPorts:   tp.Constraints.AllowedPorts,
				}
				if tp.Constraints.MaxSizeBytes != nil {
					tpSpec.Constraints.MaxSizeBytes = *tp.Constraints.MaxSizeBytes
				}
			}

			spec.ToolPermissions = append(spec.ToolPermissions, tpSpec)
		}

		// Compile to Rego
		regoModule, err := regotempl.CompileToRego(spec)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate Rego: %w", err)
		}

		// Compile with OPA
		compiled, err := policy.CompilePolicyWithOPA(ap.Name, ap.Spec.AgentTypes, defaultAction, permissions, mode, mtsLabel, regoModule)
		if err != nil {
			return nil, regoModule, fmt.Errorf("failed to compile OPA policy: %w", err)
		}

		return compiled, regoModule, nil
	}

	// Legacy compilation (no OPA)
	compiled := policy.CompilePolicy(ap.Name, ap.Spec.AgentTypes, defaultAction, permissions, mode, mtsLabel)
	return compiled, "", nil
}

// convertConstraints converts CRD constraints to internal constraints.
func convertConstraints(c *agentsv1alpha1.ToolConstraints) *policy.ToolConstraints {
	if c == nil {
		return nil
	}

	tc := &policy.ToolConstraints{
		PathPatterns:   c.PathPatterns,
		AllowedDomains: c.AllowedDomains,
		DeniedDomains:  c.DeniedDomains,
	}

	// Convert int32 ports to int
	if len(c.AllowedPorts) > 0 {
		tc.AllowedPorts = make([]int, len(c.AllowedPorts))
		for i, p := range c.AllowedPorts {
			tc.AllowedPorts[i] = int(p)
		}
	}

	if c.MaxSizeBytes != nil {
		tc.MaxSizeBytes = *c.MaxSizeBytes
	}

	// Parse timeout duration
	if c.Timeout != "" {
		if d, err := time.ParseDuration(c.Timeout); err == nil {
			tc.Timeout = d
		}
	}

	return tc
}

// updateStatus updates the AgentPolicy status subresource.
func (r *AgentPolicyReconciler) updateStatus(ctx context.Context, ap *agentsv1alpha1.AgentPolicy, hash string, reconcileErr error) error {
	// Update status fields
	now := metav1.Now()
	ap.Status.LastUpdated = &now
	ap.Status.ObservedGeneration = ap.Generation

	if hash != "" {
		ap.Status.CompiledHash = hash
	}

	// Update conditions
	condition := metav1.Condition{
		Type:               "Ready",
		LastTransitionTime: now,
		ObservedGeneration: ap.Generation,
	}

	if reconcileErr != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "CompilationFailed"
		condition.Message = reconcileErr.Error()
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "PolicyCompiled"
		condition.Message = "Policy successfully compiled and loaded"
	}

	// Update or add condition
	found := false
	for i, c := range ap.Status.Conditions {
		if c.Type == "Ready" {
			ap.Status.Conditions[i] = condition
			found = true
			break
		}
	}
	if !found {
		ap.Status.Conditions = append(ap.Status.Conditions, condition)
	}

	return r.Status().Update(ctx, ap)
}

// computeHash generates a hash of the Rego module for change detection.
func computeHash(regoModule string) string {
	if regoModule == "" {
		return ""
	}
	h := sha256.Sum256([]byte(regoModule))
	return fmt.Sprintf("%x", h[:8]) // First 8 bytes (16 hex chars)
}

// SetupWithManager sets up the controller with the Manager.
// This registers the controller to watch AgentPolicy CRDs.
func (r *AgentPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&agentsv1alpha1.AgentPolicy{}).
		Complete(r)
}
