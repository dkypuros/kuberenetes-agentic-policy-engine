========================================================================================================================
                                              AGENT POLICY - GOLDEN AGENT
========================================================================================================================
Mandatory Access Control for AI Agent Tool Invocations
Author: David Kypuros
Created: January 2026
Updated: January 2026 (OPA + CRD Controller Integration)

========================================================================================================================
                                              PROJECT STRUCTURE
========================================================================================================================

  3_Golden_Agent/
  │
  ├── README.txt                          This file
  ├── go.mod                              Module definition (OPA, client-go, controller-runtime)
  │
  ├── api/
  │   └── v1alpha1/
  │       ├── agentpolicy_types.go        (253 lines) CRD type definitions
  │       ├── doc.go                      (4 lines)   Package documentation
  │       └── groupversion_info.go        (18 lines)  Scheme registration
  │
  ├── pkg/
  │   ├── policy/
  │   │   ├── types.go                    (180 lines) Core types + OPA fields
  │   │   ├── engine.go                   (400 lines) Dual-mode eval (OPA + legacy)
  │   │   ├── opa.go                      (280 lines) OPA evaluator wrapper [NEW]
  │   │   ├── cache.go                    (138 lines) Decision cache (AVC pattern)
  │   │   ├── mts.go                      (242 lines) Multi-Tenant Sandboxing
  │   │   ├── audit.go                    (301 lines) Audit sinks
  │   │   ├── engine_test.go              (397 lines) Unit tests
  │   │   ├── mts_test.go                 (389 lines) MTS tests
  │   │   └── rego/
  │   │       └── templates.go            (240 lines) Rego policy generator [NEW]
  │   │
  │   ├── router/
  │   │   ├── policy.go                   (350 lines) Router + controller integration
  │   │   └── handler.go                  (217 lines) gRPC handler pattern
  │   │
  │   └── controller/
  │       └── agentpolicy_controller.go   (220 lines) Kubernetes controller [NEW]
  │
  ├── docs/
  │   ├── theory/
  │   │   ├── 1_the_lsm_analog.txt        LSM to Agent Policy mapping
  │   │   ├── 2_the_architectural_lineage.txt  LSM→sVirt→go-selinux→Agent Policy
  │   │   ├── 3_why_this_architecture_works.txt  8 core principles
  │   │   └── 4_the_enterprise_gap.txt    Why sandboxing isn't enough
  │   └── integration/
  │       ├── 01_agent_sandbox_integration.txt  Integration with kubernetes-sigs
  │       └── 02_opa_integration.txt      OPA integration guide [NEW]
  │
  ├── examples/
  │   ├── coding-agent-policy.yaml        Example: coding assistant policy
  │   ├── research-agent-policy.yaml      Example: research agent policy
  │   └── restricted-agent-policy.yaml    Example: minimal permissions
  │
  └── learning/
      ├── 01_title.html                   Presentation slides
      ├── ...
      └── 09_implementation.html


========================================================================================================================
                                              LINE COUNT BREAKDOWN
========================================================================================================================

  PHASE                                   │ FILES  │ LINES  │ STATUS
  ────────────────────────────────────────│────────│────────│─────────────────────────────────────
  Phase 1: Policy Engine                  │ 4      │ 1,025  │ ✓ Complete
    types.go, cache.go, engine.go         │        │        │
    engine_test.go                        │        │        │
  ────────────────────────────────────────│────────│────────│─────────────────────────────────────
  Phase 2: AgentPolicy CRD                │ 3      │   275  │ ✓ Complete
    agentpolicy_types.go, doc.go          │        │        │
    groupversion_info.go                  │        │        │
  ────────────────────────────────────────│────────│────────│─────────────────────────────────────
  Phase 3: Router Integration             │ 2      │   509  │ ✓ Complete
    policy.go, handler.go                 │        │        │
  ────────────────────────────────────────│────────│────────│─────────────────────────────────────
  Phase 4: MTS and Audit                  │ 3      │   932  │ ✓ Complete
    mts.go, audit.go, mts_test.go         │        │        │
  ────────────────────────────────────────│────────│────────│─────────────────────────────────────
  Phase 5: OPA + Controller               │ 3      │   740  │ ✓ Complete [NEW]
    opa.go, rego/templates.go             │        │        │
    controller/agentpolicy_controller.go  │        │        │
  ────────────────────────────────────────│────────│────────│─────────────────────────────────────
  TOTAL                                   │ 15     │ 3,481  │


========================================================================================================================
                                              ARCHITECTURE OVERVIEW
========================================================================================================================

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                     Router Binary (Embedded, Not Sidecar)                                        │
  ├─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                                  │
  │   gRPC Handler ──────────────> Engine.Evaluate() ──────────────> Tool Execution                                 │
  │        │                             │                                 │                                         │
  │        │                             ├── Cache hit? → return (~1μs)    │                                         │
  │        │                             │                                 │                                         │
  │        │                             ├── OPA mode? ──> PreparedQuery.Eval() (~100-500μs)                        │
  │        │                             │                                 │                                         │
  │        │                             └── Legacy? ──> ToolTable lookup (~10-100μs)                               │
  │        │                                                               │                                         │
  │        │                                                               ▼                                         │
  │        │                                                    AuditSink.Log()                                     │
  │        │                                                                                                         │
  │   StartController() ──────────────> AgentPolicyReconciler                                                       │
  │                                           │                                                                      │
  │                                           ├── Watch AgentPolicy CRDs                                            │
  │                                           ├── CompileToRego() → Rego module                                     │
  │                                           ├── PrepareRegoQuery() → PreparedEvalQuery                            │
  │                                           └── engine.LoadPolicy()                                               │
  │                                                                                                                  │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                         │
                                                         │ watches
                                                         ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                        Kubernetes API: AgentPolicy CRD (agents.sandbox.io/v1alpha1)                              │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘


========================================================================================================================
                                              BUILD ORDER (PHASES)
========================================================================================================================

PHASE 1: Policy Engine Library (Standalone, Testable) ✓ COMPLETE
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Files:
    • pkg/policy/types.go         (151→180 lines, updated for OPA)
    • pkg/policy/engine.go        (339→400 lines, dual-mode eval)
    • pkg/policy/cache.go         (138 lines)
    • pkg/policy/engine_test.go   (397 lines)

  Success Criteria:
    ✓ Engine can evaluate tool requests against in-memory policies
    ✓ Cache provides <1ms lookup for repeated requests
    ✓ Unit tests cover allow, deny, constraints, cache hit/miss
    ✓ Permissive mode logs but doesn't block


PHASE 2: AgentPolicy CRD ✓ COMPLETE
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Files:
    • api/v1alpha1/agentpolicy_types.go   (253 lines)
    • api/v1alpha1/doc.go                 (4 lines)
    • api/v1alpha1/groupversion_info.go   (18 lines)

  Success Criteria:
    ✓ Full kubebuilder validation markers
    ✓ Example policies align with CRD schema
    ✓ Supports all constraint types (path, domain, port, size, timeout)


PHASE 3: Router Integration ✓ COMPLETE
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Files:
    • pkg/router/policy.go    (292→350 lines, controller integration)
    • pkg/router/handler.go   (217 lines)

  Success Criteria:
    ✓ Router loads Policy Engine on startup
    ✓ ExecuteRequest is intercepted before routing
    ✓ Policy deny returns PermissionDenied gRPC status
    ✓ Tool name normalization (CamelCase, snake_case, dot.notation)


PHASE 4: MTS and Audit ✓ COMPLETE
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Files:
    • pkg/policy/mts.go       (242 lines)
    • pkg/policy/audit.go     (301 lines)
    • pkg/policy/mts_test.go  (389 lines)

  Success Criteria:
    ✓ MTS labels generated per tenant (deterministic, SHA-256 based)
    ✓ SELinux MCS dominance rules implemented (CanAccess)
    ✓ Audit sinks: AVC format, JSON, file, channel
    ✓ 17 unit tests passing


PHASE 5: OPA + Kubernetes Controller ✓ COMPLETE [NEW]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Files:
    • pkg/policy/opa.go                        (280 lines)
    • pkg/policy/rego/templates.go             (240 lines)
    • pkg/controller/agentpolicy_controller.go (220 lines)

  Success Criteria:
    ✓ OPA evaluator with PreparedEvalQuery caching
    ✓ AgentPolicySpec → Rego module compilation
    ✓ Kubernetes controller watches CRDs and syncs to engine
    ✓ Dual-mode engine: OPA or legacy evaluation
    ✓ <500μs OPA evaluation latency (cache miss)
    ✓ <1μs cache hit latency (unchanged)


========================================================================================================================
                                              THE SELINUX PARALLEL
========================================================================================================================

  SELINUX CONCEPT                         │ AGENT POLICY CONCEPT
  ────────────────────────────────────────│──────────────────────────────────────────────────────────────────────
  Security Context                        │ Agent Context
    user:role:type:level                  │   agent:sandbox:capabilities:tier
                                          │
  Type Enforcement                        │ Tool Enforcement
    svirt_t can read svirt_image_t        │   coding_agent can call code_exec
    httpd_t cannot read shadow_t          │   coding_agent cannot call db_admin
                                          │
  MCS (Multi-Category Security)           │ MTS (Multi-Tenant Sandboxing)
    s0:c123,c456 isolates VMs             │   tenant:project:session isolates agents
                                          │
  Policy Modules                          │ Agent Profiles / Rego Policies [UPDATED]
    selinux-policy-targeted               │   agent-profile-coding
    Custom .te files                      │   Custom AgentPolicy CRDs → Rego modules
                                          │
  AVC (Access Vector Cache)               │ Decision Cache
    Caches allow/deny decisions           │   Caches tool access decisions
    Invalidated on policy reload          │   Invalidated on CRD update
                                          │
  LSM Hooks                               │ Router Intercept
    security_file_permission()            │   Evaluate() before tool execution
    Called at syscall boundary            │   Called at gRPC boundary
                                          │
  SELinux Policy Language                 │ Rego Policy Language [NEW]
    Custom .te type enforcement rules     │   OPA Rego for policy-as-code
    Compiled to kernel policy             │   Compiled to PreparedEvalQuery


========================================================================================================================
                                              GETTING STARTED
========================================================================================================================

LEGACY MODE (No OPA):
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  config := router.DefaultPolicyConfig()
  integration := router.NewRouterPolicyIntegration(config)

  // Load policies manually
  policy := policy.CompilePolicy("coding-assistant", ...)
  integration.LoadPolicy("coding-assistant", policy)


OPA MODE (Recommended):
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  config := router.DefaultPolicyConfigWithOPA()
  integration := router.NewRouterPolicyIntegration(config)

  // Start Kubernetes controller to sync CRDs
  ctx := context.Background()
  if err := integration.StartController(ctx); err != nil {
      log.Fatal(err)
  }

  // Apply AgentPolicy CRDs to Kubernetes:
  // kubectl apply -f examples/coding-agent-policy.yaml

  // Policies are automatically synced to the engine


========================================================================================================================
                                              DEPENDENCIES
========================================================================================================================

  DEPENDENCY                              │ VERSION  │ PURPOSE
  ────────────────────────────────────────│──────────│──────────────────────────────────────────────────────────────
  github.com/open-policy-agent/opa        │ v0.60.0  │ Policy evaluation engine (Rego)
  k8s.io/client-go                        │ v0.29.0  │ Kubernetes client library
  k8s.io/apimachinery                     │ v0.29.0  │ Kubernetes API machinery
  sigs.k8s.io/controller-runtime          │ v0.17.0  │ Kubernetes controller framework
  google.golang.org/grpc                  │ v1.60.0  │ gRPC for router integration


========================================================================================================================
                                              PERFORMANCE TARGETS
========================================================================================================================

  OPERATION                               │ TARGET   │ METHOD
  ────────────────────────────────────────│──────────│──────────────────────────────────────────────────────────────
  Cache hit                               │ <1μs     │ DecisionCache (sync.Map)
  Legacy cache miss                       │ <100μs   │ ToolTable map lookup
  OPA cache miss                          │ <500μs   │ PreparedEvalQuery.Eval()
  Policy load (one-time)                  │ <100ms   │ PrepareForEval() compilation
  Total request overhead                  │ <1ms     │ All policy checks combined


========================================================================================================================
                                              END OF README
========================================================================================================================
