# IEC 62443 Mapping Experiment

Exploring how the SELinux-inspired Agent Policy Engine maps to IEC 62443 industrial
cybersecurity concepts.

## About This Experiment

### YAML Files vs Kubernetes CRDs

**How the Agent Policy Engine is designed to work:**

The policy engine is built around Kubernetes Custom Resource Definitions (CRDs).
In production, you define policies as `AgentPolicy` resources in Kubernetes:

```bash
kubectl apply -f control-zone-agent.yaml
```

Kubernetes stores the policy, the `AgentPolicyReconciler` controller detects the
change, compiles it, and hot-reloads it into the running router. This gives you
versioning, RBAC, GitOps workflows, audit trails - all the Kubernetes goodness.

**What we're doing instead (for this experiment):**

Running a Kubernetes cluster just to test "does the policy engine block an
enterprise agent from writing to a PLC?" is overkill. So instead, we load the
same YAML files directly with a Go parser and feed them to the policy engine.

The key insight: **the YAML structure is identical**. We use the same `apiVersion`,
`kind`, `metadata`, and `spec` fields that the Kubernetes CRD expects. The only
difference is *how* the file gets to the policy engine:

| Approach | Path to Policy Engine |
|----------|----------------------|
| **Production (CRD)** | `kubectl apply` → K8s API → Controller → `CompilePolicy()` |
| **Experiment (YAML)** | `yaml.Unmarshal()` → `CompilePolicy()` |

Same policy, same compilation, same enforcement. We just skip the Kubernetes
machinery for faster iteration.

**Why this matters:** The policy files in this experiment are **plain YAML files**
that we load directly with a Go YAML parser for testing. They are NOT deployed
to Kubernetes - but they're formatted exactly like they would be if they were.

However, we intentionally format them to match the Kubernetes Custom Resource structure:

```yaml
apiVersion: agents.sandbox.io/v1alpha1   # ← Looks like a K8s API group
kind: AgentPolicy                        # ← Looks like a K8s resource type
metadata:
  name: control-zone-agent-policy        # ← Standard K8s metadata
spec:
  agentTypes: [...]                      # ← Policy specification
```

**Why format them this way?**

So the same policy file works in both contexts:

| Context | How Policy is Loaded |
|---------|---------------------|
| **This experiment** | `yaml.Unmarshal()` → `policy.CompilePolicy()` → Engine |
| **Production (K8s)** | `kubectl apply` → K8s API → Controller watches → Engine |

### What Would Be Different in Production?

In a real Kubernetes deployment:

1. **CRD Schema** - You'd first deploy a CustomResourceDefinition that tells K8s
   what an `AgentPolicy` looks like (field types, validation, etc.)

2. **Controller** - The `AgentPolicyReconciler` in `pkg/controller/` watches for
   these resources and syncs them to the policy engine automatically

3. **Lifecycle** - Policies are versioned, audited, and managed by K8s (GitOps, RBAC, etc.)

### How This Experiment Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  Experiment (what we're doing here)                                 │
│                                                                     │
│    policies/*.yaml  →  Go test loads with yaml.Unmarshal()          │
│                              ↓                                      │
│                     policy.CompilePolicy()                          │
│                              ↓                                      │
│                     router.Execute() checks policy                  │
│                              ↓                                      │
│                     ALLOW or DENY                                   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  Production (Kubernetes deployment)                                 │
│                                                                     │
│    kubectl apply -f policies/*.yaml                                 │
│                              ↓                                      │
│                     Kubernetes API stores CR                        │
│                              ↓                                      │
│                     AgentPolicyReconciler watches                   │
│                              ↓                                      │
│                     policy.CompilePolicy()                          │
│                              ↓                                      │
│                     Hot-reload into running router                  │
└─────────────────────────────────────────────────────────────────────┘
```

The policy logic is identical. Only the delivery mechanism changes.

## Conceptual Mapping

| IEC 62443 Concept | Agent Policy Equivalent |
|-------------------|------------------------|
| **Zone** | Agent Type (e.g., `control-zone-agent`) |
| **Conduit** | Tool Permission with domain/path constraints |
| **Security Level (SL)** | Enforcement Mode + Policy Strictness |
| **Asset** | Tool or resource being accessed |

## Purdue Model Zones → Agent Types

```
┌─────────────────────────────────────────────────────────────┐
│  Level 5: Enterprise Network                                │
│  Agent Type: enterprise-zone-agent                          │
│  Tools: erp.query, email.send, report.generate              │
├─────────────────────────────────────────────────────────────┤
│  Level 4: Site Business Planning                            │
│  Agent Type: business-zone-agent                            │
│  Tools: inventory.read, schedule.update, analytics.query    │
├──────────────────────── DMZ ────────────────────────────────┤
│  Level 3.5: Industrial DMZ                                  │
│  Agent Type: dmz-broker-agent                               │
│  Tools: data.relay, protocol.translate (CONDUIT ONLY)       │
├─────────────────────────────────────────────────────────────┤
│  Level 3: Site Operations                                   │
│  Agent Type: operations-zone-agent                          │
│  Tools: historian.read, alarm.acknowledge, batch.monitor    │
├─────────────────────────────────────────────────────────────┤
│  Level 2: Area Supervisory Control                          │
│  Agent Type: control-zone-agent                             │
│  Tools: hmi.read, setpoint.read, trend.query                │
├─────────────────────────────────────────────────────────────┤
│  Level 1: Basic Control (PLCs, RTUs)                        │
│  Agent Type: basic-control-agent                            │
│  Tools: plc.read (READ ONLY - no writes!)                   │
├─────────────────────────────────────────────────────────────┤
│  Level 0: Process (Physical Equipment)                      │
│  NO AGENTS ALLOWED - physical layer                         │
└─────────────────────────────────────────────────────────────┘
```

## Security Levels → Policy Strictness

| SL | Description | Policy Mapping |
|----|-------------|----------------|
| SL 1 | Protection against casual or coincidental violation | `mode: permissive`, broad tool access |
| SL 2 | Protection against intentional violation using simple means | `mode: enforcing`, default deny, explicit allows |
| SL 3 | Protection against sophisticated attacks with moderate resources | SL2 + strict path constraints + MTS labels |
| SL 4 | Protection against state-sponsored attacks | SL3 + OPA policy-as-code + audit everything |

## Conduit Rules

Conduits are the ONLY approved paths between zones. In agent policy terms:

- An agent in Zone A can only call tools that connect to Zone B if there's an explicit conduit rule
- The conduit rule specifies: allowed domains, allowed ports, allowed operations
- No conduit = no communication (default deny)

Example: Control Zone agent needs data from Historian (Operations Zone):

```yaml
toolPermissions:
  - tool: historian.read        # Conduit: Control → Operations
    action: allow
    constraints:
      allowedDomains: ["historian.operations.local"]
      allowedPorts: [443]
  - tool: historian.write       # NO CONDUIT - blocked
    action: deny
```

## Files in this Experiment

| File | Description |
|------|-------------|
| `policies/control-zone-agent.yaml` | Level 2 agent - HMI/SCADA read access only |
| `policies/enterprise-zone-agent.yaml` | Level 5 agent - business systems, no OT access |
| `policies/dmz-broker-agent.yaml` | Level 3.5 agent - conduit-only, data relay |
| `policies/security-levels.yaml` | Shows SL1-SL4 as different policy strictness |

## Key Insight

The SELinux model maps naturally to 62443:

- **Type Enforcement** → Zone-based agent types
- **Domain Transitions** → Conduit rules (agent A can invoke tool that talks to zone B)
- **MLS/MCS Labels** → Security Level enforcement
- **Audit** → Already built into the policy engine

The policy engine doesn't know anything about industrial protocols - it just enforces
which tools an agent can call. The tools themselves handle MODBUS, OPC-UA, etc.
