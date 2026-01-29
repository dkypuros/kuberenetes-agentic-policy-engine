# Agentic Policy Engine

Mandatory Access Control for AI agent tool invocations. SELinux-inspired policy engine with OPA/Rego, Kubernetes CRD integration, and embedded binary enforcement.

## What This Does

Controls what tools an AI agent can use. When an agent tries to call `file.read`, `code.execute`, or `network.fetch`, this policy engine decides: **ALLOW** or **DENY**.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                   KUBERNETES CLUSTER                                     │
│                                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │ CONTROL PLANE                                                                     │   │
│  │                                                                                   │   │
│  │   ┌─────────────────────────┐         ┌─────────────────────────┐                │   │
│  │   │   AgentPolicy CRD       │         │   Policy Controller     │                │   │
│  │   │                         │ ──────> │                         │                │   │
│  │   │   - coding-assistant    │  watch  │   - Compiles to Rego    │                │   │
│  │   │   - allow: file.read    │         │   - Syncs to engine     │                │   │
│  │   │   - allow: code.execute │         │                         │                │   │
│  │   │   - deny: network.fetch │         └───────────┬─────────────┘                │   │
│  │   └─────────────────────────┘                     │                              │   │
│  │              ▲                                    │ load policies                │   │
│  │              │ kubectl apply                      ▼                              │   │
│  └──────────────┼───────────────────────────────────────────────────────────────────┘   │
│                 │                                                                        │
│       ┌─────────┴─────────┐                                                             │
│       │   Platform Admin  │                                                             │
│       └───────────────────┘                                                             │
│                                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │ AGENT SANDBOX POD                                                                 │   │
│  │                                                                                   │   │
│  │   ┌─────────────┐      ┌─────────────────────────┐      ┌─────────────────────┐  │   │
│  │   │             │      │                         │      │   TOOL EXECUTORS    │  │   │
│  │   │  AI AGENT   │ ───> │   ROUTER + POLICY       │ ───> │                     │  │   │
│  │   │             │  1   │       ENGINE            │  3a  │  file.read          │  │   │
│  │   │  (coding    │      │                         │      │  code.execute       │  │   │
│  │   │  assistant) │      │  ┌─────────────────┐    │      │  network.fetch      │  │   │
│  │   │             │      │  │ 2. POLICY CHECK │    │      │  db.query           │  │   │
│  │   │             │ <─ ─ │  │                 │    │      │                     │  │   │
│  │   │             │  3b  │  │ ALLOW? → pass   │    │      │                     │  │   │
│  │   │             │ DENY │  │ DENY?  → block  │    │      │                     │  │   │
│  │   │             │      │  └─────────────────┘    │      │                     │  │   │
│  │   └─────────────┘      └─────────────────────────┘      └─────────────────────┘  │   │
│  │                                                                                   │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## Three Components Working Together

### 1. CRD (Declarative Policy Storage)

Policies are defined as Kubernetes Custom Resources:

```yaml
apiVersion: agents.sandbox.io/v1alpha1
kind: AgentPolicy
metadata:
  name: coding-assistant-policy
spec:
  agentTypes: ["coding-assistant"]
  defaultAction: deny
  toolPermissions:
    - tool: file.read
      action: allow
      constraints:
        pathPatterns: ["/workspace/**"]
    - tool: code.execute
      action: allow
    - tool: network.fetch
      action: deny
```

### 2. Binary-to-Binary (Embedded Policy Engine)

The policy engine is **compiled into** the router binary - not a sidecar:

```
  SIDECAR PATTERN (not used):              EMBEDDED PATTERN (what we do):

  ┌─────────┐    ┌─────────┐               ┌─────────────────────────────┐
  │ Router  │───>│  OPA    │               │ Router + OPA (one binary)   │
  │         │    │ Sidecar │               │                             │
  └─────────┘    └─────────┘               └─────────────────────────────┘
       network hop = ~1-5ms                     function call = ~100μs

  Problem: Agent could bypass                No bypass possible - policy
  sidecar and hit tools directly             check is IN the code path
```

### 3. OPA/Rego Policy Evaluation

Policies are compiled to Rego for fast evaluation:

```
  Operation                    Latency      Frequency
  ─────────────────────────────────────────────────────
  Cache hit                    ~1μs         Per request (frequent)
  OPA evaluation               ~100-500μs   Per cache miss (occasional)
  Policy compilation           ~50ms        Once per policy load (rare)
```

## The SELinux Parallel

| SELinux Concept | Agentic Policy Concept |
|-----------------|------------------------|
| Security Context (`user:role:type:level`) | Agent Context (`agent:sandbox:capabilities:tier`) |
| Type Enforcement (`httpd_t can read httpd_config_t`) | Tool Enforcement (`coding_agent can call code.execute`) |
| MCS Labels (`s0:c123,c456`) | MTS Labels (Multi-Tenant Sandboxing) |
| AVC (Access Vector Cache) | Decision Cache |
| LSM Hooks (`security_file_permission()`) | Router Intercept (`Evaluate()`) |

## Project Structure

```
├── api/v1alpha1/
│   ├── agentpolicy_types.go      # CRD type definitions
│   ├── groupversion_info.go      # Scheme registration
│   └── zz_generated.deepcopy.go  # DeepCopy methods
│
├── pkg/policy/
│   ├── engine.go                 # Dual-mode eval (OPA + legacy)
│   ├── opa.go                    # OPA evaluator wrapper
│   ├── cache.go                  # Decision cache (AVC pattern)
│   ├── mts.go                    # Multi-Tenant Sandboxing
│   ├── audit.go                  # Audit event sinks
│   └── rego/templates.go         # Rego policy generator
│
├── pkg/controller/
│   └── agentpolicy_controller.go # Kubernetes controller
│
├── pkg/router/
│   ├── policy.go                 # Router integration
│   └── handler.go                # gRPC handler pattern
│
└── examples/
    ├── coding-agent-policy.yaml
    ├── research-agent-policy.yaml
    └── restricted-agent-policy.yaml
```

## Quick Start

### Legacy Mode (No OPA)

```go
config := router.DefaultPolicyConfig()
integration := router.NewRouterPolicyIntegration(config)

policy := policy.CompilePolicy("coding-assistant", ...)
integration.LoadPolicy("coding-assistant", policy)
```

### OPA Mode (Recommended)

```go
config := router.DefaultPolicyConfigWithOPA()
integration := router.NewRouterPolicyIntegration(config)

ctx := context.Background()
if err := integration.StartController(ctx); err != nil {
    log.Fatal(err)
}

// Apply policies via kubectl:
// kubectl apply -f examples/coding-agent-policy.yaml
```

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `github.com/open-policy-agent/opa` | v0.60.0 | Policy evaluation (Rego) |
| `k8s.io/client-go` | v0.29.0 | Kubernetes client |
| `sigs.k8s.io/controller-runtime` | v0.17.0 | Controller framework |
| `google.golang.org/grpc` | v1.60.0 | Router integration |

## Build & Test

```bash
# Build
go build ./pkg/... ./api/...

# Test
go test ./pkg/... -v

# Run all 17 tests
go test ./pkg/policy/... -v
```

## License

Apache 2.0
