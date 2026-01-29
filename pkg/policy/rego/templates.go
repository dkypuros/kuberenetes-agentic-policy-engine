// Package rego provides Rego policy generation from AgentPolicySpec.
// This converts Kubernetes CRD specifications into executable Rego policies
// that can be compiled and evaluated by OPA.
//
// The generated Rego follows this structure:
//
//	package agentpolicy
//	default allow := false
//	allow { tool-specific rules }
//	deny { explicit denials }
//	mts_allow { tenant isolation check }
//	decision := {allow, deny, mts, reason}
package rego

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// PolicySpec represents the input for Rego generation.
// This mirrors the AgentPolicySpec from the CRD but uses simpler types
// to avoid import cycles with the api package.
type PolicySpec struct {
	// Name is the policy name (from CRD metadata.name)
	Name string

	// AgentTypes are the agent types this policy applies to
	AgentTypes []string

	// DefaultAction is "allow" or "deny" for unlisted tools
	DefaultAction string

	// Mode is "enforcing" or "permissive"
	Mode string

	// ToolPermissions are the explicit tool rules
	ToolPermissions []ToolPermissionSpec

	// MTSLabel is the multi-tenant sandboxing label (optional)
	MTSLabel string

	// MTSEnforceMode is "strict", "permissive", or "disabled"
	MTSEnforceMode string
}

// ToolPermissionSpec represents a single tool permission rule.
type ToolPermissionSpec struct {
	// Tool is the tool name (e.g., "file.read")
	Tool string

	// Action is "allow" or "deny"
	Action string

	// Constraints are optional conditions for allow rules
	Constraints *ConstraintSpec
}

// ConstraintSpec represents constraint conditions for a tool permission.
type ConstraintSpec struct {
	PathPatterns   []string
	AllowedDomains []string
	DeniedDomains  []string
	AllowedPorts   []int32
	MaxSizeBytes   int64
	Timeout        string
}

// regoTemplate is the base template for generating Rego policies.
// It produces a complete Rego module that returns a decision object.
const regoTemplate = `# Auto-generated from AgentPolicy CRD: {{.Name}}
# Do not edit directly - changes will be overwritten
package agentpolicy

import future.keywords.if
import future.keywords.in

# Default action: {{.DefaultAction}}
default allow := {{if eq .DefaultAction "allow"}}true{{else}}false{{end}}
default deny := false
default mts_allow := true

# ============================================================================
# Tool-specific allow rules
# ============================================================================
{{range .AllowRules}}
# Rule: {{.Tool}} - allowed
allow if {
    input.tool == "{{.Tool}}"
{{- if .HasConstraints}}
    {{.ConstraintRego}}
{{- end}}
}
{{end}}

# ============================================================================
# Tool-specific deny rules
# ============================================================================
{{range .DenyRules}}
# Rule: {{.Tool}} - denied
deny if {
    input.tool == "{{.Tool}}"
}
{{end}}

# ============================================================================
# Multi-Tenant Sandboxing (MTS) enforcement
# ============================================================================
{{if .MTSEnabled}}
# MTS Label: {{.MTSLabel}}
# Enforce Mode: {{.MTSEnforceMode}}
{{if eq .MTSEnforceMode "strict"}}
# Strict mode: require exact label match
mts_allow if {
    input.agent.mts_label == "{{.MTSLabel}}"
}

mts_allow if {
    # Empty policy MTS label means no restriction
    "{{.MTSLabel}}" == ""
}
{{else if eq .MTSEnforceMode "permissive"}}
# Permissive mode: log but allow (MTS check always passes)
mts_allow := true
{{else}}
# Disabled mode: no MTS checking
mts_allow := true
{{end}}
{{else}}
# MTS not configured - allow all
mts_allow := true
{{end}}

# ============================================================================
# Path constraint helpers
# ============================================================================
{{range .PathHelpers}}
path_allowed_{{.SafeName}}(path) if {
{{- range .Patterns}}
    glob.match("{{.}}", [], path)
}

path_allowed_{{.SafeName}}(path) if {
{{- end}}
    false  # fallback
}
{{end}}

# ============================================================================
# Domain constraint helpers
# ============================================================================
{{range .DomainHelpers}}
domain_allowed_{{.SafeName}}(domain) if {
{{- range .AllowedDomains}}
    {{if hasPrefix . "*."}}
    # Wildcard: {{.}}
    endswith(domain, "{{trimPrefix . "*"}}")
{{- else}}
    domain == "{{.}}"
{{- end}}
}

domain_allowed_{{.SafeName}}(domain) if {
{{- end}}
    false  # fallback
}

domain_denied_{{.SafeName}}(domain) if {
{{- range .DeniedDomains}}
    {{if hasPrefix . "*."}}
    endswith(domain, "{{trimPrefix . "*"}}")
{{- else}}
    domain == "{{.}}"
{{- end}}
}
{{end}}

# ============================================================================
# Final decision object
# ============================================================================
decision := {
    "allow": final_allow,
    "deny": deny,
    "mts": mts_allow,
    "reason": reason
}

# Final allow considers MTS
final_allow if {
    allow
    not deny
    mts_allow
}

# Reason determination
reason := "tool explicitly allowed" if {
    allow
    not deny
    mts_allow
}

reason := "tool explicitly denied" if {
    deny
}

reason := "MTS violation: tenant isolation" if {
    allow
    not deny
    not mts_allow
}

reason := "denied by default policy" if {
    not allow
    not deny
}
`

// templateData holds the processed data for template execution.
type templateData struct {
	Name           string
	DefaultAction  string
	AllowRules     []ruleData
	DenyRules      []ruleData
	PathHelpers    []pathHelperData
	DomainHelpers  []domainHelperData
	MTSEnabled     bool
	MTSLabel       string
	MTSEnforceMode string
}

type ruleData struct {
	Tool           string
	HasConstraints bool
	ConstraintRego string
}

type pathHelperData struct {
	SafeName string
	Patterns []string
}

type domainHelperData struct {
	SafeName       string
	AllowedDomains []string
	DeniedDomains  []string
}

// CompileToRego converts a PolicySpec to a complete Rego module.
// This is the main entry point for policy generation.
func CompileToRego(spec *PolicySpec) (string, error) {
	// Process the spec into template data
	data := processSpec(spec)

	// Create template with helper functions
	funcMap := template.FuncMap{
		"hasPrefix":  strings.HasPrefix,
		"trimPrefix": strings.TrimPrefix,
	}

	tmpl, err := template.New("rego").Funcs(funcMap).Parse(regoTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse Rego template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute Rego template: %w", err)
	}

	return buf.String(), nil
}

// processSpec converts PolicySpec to templateData for template execution.
func processSpec(spec *PolicySpec) templateData {
	data := templateData{
		Name:           spec.Name,
		DefaultAction:  spec.DefaultAction,
		AllowRules:     []ruleData{},
		DenyRules:      []ruleData{},
		PathHelpers:    []pathHelperData{},
		DomainHelpers:  []domainHelperData{},
		MTSEnabled:     spec.MTSLabel != "",
		MTSLabel:       spec.MTSLabel,
		MTSEnforceMode: spec.MTSEnforceMode,
	}

	if data.MTSEnforceMode == "" {
		data.MTSEnforceMode = "strict" // default
	}

	// Process each tool permission
	for _, tp := range spec.ToolPermissions {
		safeName := makeSafeName(tp.Tool)

		if tp.Action == "allow" {
			rule := ruleData{
				Tool:           tp.Tool,
				HasConstraints: tp.Constraints != nil && hasAnyConstraint(tp.Constraints),
			}

			if rule.HasConstraints {
				rule.ConstraintRego = generateConstraintRego(tp.Tool, tp.Constraints, safeName)

				// Add helper functions for path/domain constraints
				if len(tp.Constraints.PathPatterns) > 0 {
					data.PathHelpers = append(data.PathHelpers, pathHelperData{
						SafeName: safeName,
						Patterns: tp.Constraints.PathPatterns,
					})
				}
				if len(tp.Constraints.AllowedDomains) > 0 || len(tp.Constraints.DeniedDomains) > 0 {
					data.DomainHelpers = append(data.DomainHelpers, domainHelperData{
						SafeName:       safeName,
						AllowedDomains: tp.Constraints.AllowedDomains,
						DeniedDomains:  tp.Constraints.DeniedDomains,
					})
				}
			}

			data.AllowRules = append(data.AllowRules, rule)
		} else {
			data.DenyRules = append(data.DenyRules, ruleData{
				Tool: tp.Tool,
			})
		}
	}

	return data
}

// hasAnyConstraint checks if a ConstraintSpec has any constraints defined.
func hasAnyConstraint(c *ConstraintSpec) bool {
	return len(c.PathPatterns) > 0 ||
		len(c.AllowedDomains) > 0 ||
		len(c.DeniedDomains) > 0 ||
		len(c.AllowedPorts) > 0 ||
		c.MaxSizeBytes > 0
}

// generateConstraintRego generates inline Rego for constraint checking.
func generateConstraintRego(tool string, c *ConstraintSpec, safeName string) string {
	var lines []string

	// Path constraints
	if len(c.PathPatterns) > 0 {
		lines = append(lines, fmt.Sprintf("    path_allowed_%s(input.request.path)", safeName))
	}

	// Domain constraints (allowed)
	if len(c.AllowedDomains) > 0 {
		lines = append(lines, fmt.Sprintf("    domain_allowed_%s(input.request.domain)", safeName))
	}

	// Domain constraints (denied)
	if len(c.DeniedDomains) > 0 {
		lines = append(lines, fmt.Sprintf("    not domain_denied_%s(input.request.domain)", safeName))
	}

	// Port constraints
	if len(c.AllowedPorts) > 0 {
		portList := make([]string, len(c.AllowedPorts))
		for i, p := range c.AllowedPorts {
			portList[i] = fmt.Sprintf("%d", p)
		}
		lines = append(lines, fmt.Sprintf("    input.request.port in {%s}", strings.Join(portList, ", ")))
	}

	// Size constraints
	if c.MaxSizeBytes > 0 {
		lines = append(lines, fmt.Sprintf("    input.request.size <= %d", c.MaxSizeBytes))
	}

	return strings.Join(lines, "\n")
}

// makeSafeName converts a tool name to a safe Rego identifier.
// "file.read" -> "file_read"
func makeSafeName(tool string) string {
	return strings.ReplaceAll(tool, ".", "_")
}

// GenerateMinimalRego generates a minimal Rego policy for simple cases.
// This is useful for testing or when full constraint support isn't needed.
func GenerateMinimalRego(defaultAllow bool, allowedTools, deniedTools []string) string {
	var buf bytes.Buffer

	buf.WriteString("package agentpolicy\n\n")
	buf.WriteString("import future.keywords.if\n")
	buf.WriteString("import future.keywords.in\n\n")

	if defaultAllow {
		buf.WriteString("default allow := true\n")
	} else {
		buf.WriteString("default allow := false\n")
	}
	buf.WriteString("default deny := false\n")
	buf.WriteString("default mts_allow := true\n\n")

	// Allow rules
	for _, tool := range allowedTools {
		buf.WriteString(fmt.Sprintf("allow if { input.tool == %q }\n", tool))
	}

	// Deny rules
	for _, tool := range deniedTools {
		buf.WriteString(fmt.Sprintf("deny if { input.tool == %q }\n", tool))
	}

	// Decision object
	buf.WriteString(`
decision := {
    "allow": allow,
    "deny": deny,
    "mts": mts_allow,
    "reason": "policy evaluation"
}
`)

	return buf.String()
}
