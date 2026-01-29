# Agentic Policy Engine

Mandatory Access Control for AI agent tool invocations. SELinux-inspired policy engine with OPA/Rego, Kubernetes CRD integration, and embedded binary enforcement.

## What This Does

Controls what tools an AI agent can use. When an agent tries to call `file.read`, `code.execute`, or `network.fetch`, this policy engine decides: **ALLOW** or **DENY**.

```
+-----------------------------------------------------------------------------------+
|                            KUBERNETES CLUSTER                                     |
|                                                                                   |
|  +----------------------------------+    +----------------------------------+     |
|  | AgentPolicy CRD                  |    | Policy Controller                |     |
|  |   agentTypes: [coding-assistant] |--->|   - Compiles to Rego             |     |
|  |   allow: file.read, code.execute |    |   - Syncs to engine              |     |
|  |   deny: network.fetch            |    +----------------+-----------------+     |
|  +----------------------------------+                     |                       |
|            ^                                              | load                  |
|            | kubectl apply                                v                       |
|  +---------+--------+                                                             |
|  | Platform Admin   |                                                             |
|  +------------------+                                                             |
|                                                                                   |
|  +--------------------------------------------------------------------------+     |
|  | AGENT SANDBOX POD                                                        |     |
|  |                                                                          |     |
|  |  +-----------+     +------------------+     +----------------------+     |     |
|  |  |           |     |                  |     |   TOOL EXECUTORS     |     |     |
|  |  | AI AGENT  |---->| ROUTER + POLICY  |---->|   file.read          |     |     |
|  |  |           |  1  |     ENGINE       | 3a  |   code.execute       |     |     |
|  |  | (coding   |     |                  |     |   network.fetch      |     |     |
|  |  | assistant)|     | 2. ALLOW/DENY?   |     |   db.query           |     |     |
|  |  |           |<----|    check policy  |     |                      |     |     |
|  |  |           | 3b  |                  |     |                      |     |     |
|  |  +-----------+DENY +------------------+     +----------------------+     |     |
|  |                                                                          |     |
|  +--------------------------------------------------------------------------+     |
+-----------------------------------------------------------------------------------+
```

## Three Components

### 1. CRD (Policy Storage)

```yaml
apiVersion: agents.sandbox.io/v1alpha1
kind: AgentPolicy
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

### 2. Binary-to-Binary (Embedded Engine)

```
SIDECAR (not used):           EMBEDDED (what we do):

+--------+    +--------+      +------------------------+
| Router |--->|  OPA   |      | Router + OPA (1 binary)|
+--------+    +--------+      +------------------------+
   network hop ~1-5ms            function call ~100us

Agent could bypass sidecar    No bypass - policy check
                              is IN the code path
```

### 3. OPA/Rego Evaluation

| Operation | Latency | Frequency |
|-----------|---------|-----------|
| Cache hit | ~1μs | Per request |
| OPA eval | ~100-500μs | Cache miss |
| Compile | ~50ms | Policy load |

## SELinux Parallel

| SELinux | Agentic Policy |
|---------|----------------|
| Security Context | Agent Context |
| Type Enforcement | Tool Enforcement |
| MCS Labels | MTS (Multi-Tenant Sandboxing) |
| AVC (Access Vector Cache) | Decision Cache |
| LSM Hooks | Router Intercept |

## Project Structure

```
api/v1alpha1/           # CRD types
pkg/policy/             # Engine, OPA, cache, MTS, audit
pkg/controller/         # Kubernetes controller
pkg/router/             # Router integration
examples/               # Sample policies
slides/                 # Presentation
```

## Quick Start

```go
// OPA Mode (Recommended)
config := router.DefaultPolicyConfigWithOPA()
integration := router.NewRouterPolicyIntegration(config)
integration.StartController(ctx)

// kubectl apply -f examples/coding-agent-policy.yaml
```

## Build & Test

```bash
go build ./pkg/... ./api/...
go test ./pkg/policy/... -v  # 17 tests
```

## License

Apache 2.0

## Slides

<a href="https://dkypuros.github.io/kuberenetes-agentic-policy-engine/slides/01_title.html" target="_blank">View the presentation slides</a>

<a href="https://dkypuros.github.io/kuberenetes-agentic-policy-engine/slides/golden_agent_talk_tracks.mp3" target="_blank">Listen to talk track (MP3)</a>
