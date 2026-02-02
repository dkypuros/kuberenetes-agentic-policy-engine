package iec62443

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/golden-agent/golden-agent/pkg/policy"
	"github.com/golden-agent/golden-agent/pkg/router"
)

// PolicyFile represents the structure of our YAML policy files
type PolicyFile struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec struct {
		AgentTypes      []string `yaml:"agentTypes"`
		DefaultAction   string   `yaml:"defaultAction"`
		Mode            string   `yaml:"mode"`
		TenantIsolation *struct {
			MTSLabel    string `yaml:"mtsLabel"`
			EnforceMode string `yaml:"enforceMode"`
		} `yaml:"tenantIsolation"`
		ToolPermissions []struct {
			Tool        string `yaml:"tool"`
			Action      string `yaml:"action"`
			Constraints *struct {
				AllowedDomains []string `yaml:"allowedDomains"`
				AllowedPorts   []int    `yaml:"allowedPorts"`
				PathPatterns   []string `yaml:"pathPatterns"`
			} `yaml:"constraints"`
		} `yaml:"toolPermissions"`
	} `yaml:"spec"`
}

// loadPolicy reads a YAML file and converts it to a CompiledPolicy
func loadPolicy(t *testing.T, filename string) (*policy.CompiledPolicy, string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		t.Fatalf("failed to parse %s: %v", filename, err)
	}

	// Convert to internal types
	defaultAction := policy.Deny
	if pf.Spec.DefaultAction == "allow" {
		defaultAction = policy.Allow
	}

	mode := policy.Enforcing
	if pf.Spec.Mode == "permissive" {
		mode = policy.Permissive
	}

	var permissions []policy.ToolPermission
	for _, tp := range pf.Spec.ToolPermissions {
		action := policy.Deny
		if tp.Action == "allow" {
			action = policy.Allow
		}

		perm := policy.ToolPermission{
			Tool:   tp.Tool,
			Action: action,
		}

		if tp.Constraints != nil {
			perm.Constraints = &policy.ToolConstraints{
				AllowedDomains: tp.Constraints.AllowedDomains,
				AllowedPorts:   tp.Constraints.AllowedPorts,
				PathPatterns:   tp.Constraints.PathPatterns,
			}
		}

		permissions = append(permissions, perm)
	}

	mtsLabel := ""
	if pf.Spec.TenantIsolation != nil {
		mtsLabel = pf.Spec.TenantIsolation.MTSLabel
	}

	compiled := policy.CompilePolicy(
		pf.Metadata.Name,
		pf.Spec.AgentTypes,
		defaultAction,
		permissions,
		mode,
		mtsLabel,
	)

	return compiled, pf.Spec.AgentTypes[0]
}

func TestControlZoneAgent(t *testing.T) {
	// Load the control zone policy
	policyPath := filepath.Join("policies", "control-zone-agent.yaml")
	compiled, agentType := loadPolicy(t, policyPath)

	// Create router with policy
	config := router.DefaultPolicyConfig()
	config.Mode = policy.Enforcing
	r := router.NewToolRouter(config)
	r.LoadPolicy(agentType, compiled)

	ctx := context.Background()

	tests := []struct {
		name       string
		tool       string
		params     map[string]interface{}
		wantAllow  bool
		desc       string
	}{
		{
			name:      "hmi_read_allowed",
			tool:      "hmi.read",
			params:    map[string]interface{}{"domain": "hmi-01.plant-alpha.local"},
			wantAllow: true,
			desc:      "Control zone agent CAN read HMI",
		},
		{
			name:      "setpoint_read_allowed",
			tool:      "setpoint.read",
			params:    map[string]interface{}{},
			wantAllow: true,
			desc:      "Control zone agent CAN read setpoints",
		},
		{
			name:      "setpoint_write_denied",
			tool:      "setpoint.write",
			params:    map[string]interface{}{"value": 100},
			wantAllow: false,
			desc:      "Control zone agent CANNOT write setpoints (human only)",
		},
		{
			name:      "plc_write_denied",
			tool:      "plc.write",
			params:    map[string]interface{}{"address": "40001", "value": 1},
			wantAllow: false,
			desc:      "Control zone agent CANNOT write to PLC",
		},
		{
			name:      "historian_read_allowed",
			tool:      "historian.read",
			params:    map[string]interface{}{"query": "SELECT * FROM trends"},
			wantAllow: true,
			desc:      "Conduit to Operations Zone - historian read allowed",
		},
		{
			name:      "internet_denied",
			tool:      "internet.fetch",
			params:    map[string]interface{}{"url": "https://google.com"},
			wantAllow: false,
			desc:      "Control zone is air-gapped - no internet",
		},
		{
			name:      "enterprise_denied",
			tool:      "enterprise.query",
			params:    map[string]interface{}{},
			wantAllow: false,
			desc:      "No direct access to enterprise zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &router.ExecuteRequest{
				ToolName:   tt.tool,
				Parameters: tt.params,
				Metadata: router.RequestMetadata{
					AgentType: agentType,
					SandboxID: "sandbox-control-001",
				},
			}

			_, err := r.Execute(ctx, req)
			allowed := (err == nil)

			if allowed != tt.wantAllow {
				if tt.wantAllow {
					t.Errorf("%s: expected ALLOW, got DENY - %s", tt.desc, err)
				} else {
					t.Errorf("%s: expected DENY, got ALLOW", tt.desc)
				}
			} else {
				if tt.wantAllow {
					t.Logf("✓ %s", tt.desc)
				} else {
					t.Logf("✓ BLOCKED: %s", tt.desc)
				}
			}
		})
	}
}

func TestEnterpriseZoneAgent(t *testing.T) {
	policyPath := filepath.Join("policies", "enterprise-zone-agent.yaml")
	compiled, agentType := loadPolicy(t, policyPath)

	config := router.DefaultPolicyConfig()
	config.Mode = policy.Enforcing
	r := router.NewToolRouter(config)
	r.LoadPolicy(agentType, compiled)

	ctx := context.Background()

	tests := []struct {
		name      string
		tool      string
		wantAllow bool
		desc      string
	}{
		{"erp_query", "erp.query", true, "Enterprise agent CAN query ERP"},
		{"email_send", "email.send", true, "Enterprise agent CAN send email"},
		{"report_generate", "report.generate", true, "Enterprise agent CAN generate reports"},
		{"dmz_summary", "dmz.production-summary", true, "Enterprise agent CAN get production summary via DMZ"},
		{"historian_read", "historian.read", false, "Enterprise agent CANNOT read historian directly"},
		{"hmi_read", "hmi.read", false, "Enterprise agent CANNOT access HMI"},
		{"plc_read", "plc.read", false, "Enterprise agent has ZERO PLC access"},
		{"plc_write", "plc.write", false, "Enterprise agent has ZERO PLC access"},
		{"scada_query", "scada.query", false, "Enterprise agent CANNOT query SCADA"},
		{"modbus_read", "modbus.read", false, "Enterprise agent has no industrial protocol access"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &router.ExecuteRequest{
				ToolName:   tt.tool,
				Parameters: map[string]interface{}{},
				Metadata: router.RequestMetadata{
					AgentType: agentType,
					SandboxID: "sandbox-enterprise-001",
				},
			}

			_, err := r.Execute(ctx, req)
			allowed := (err == nil)

			if allowed != tt.wantAllow {
				if tt.wantAllow {
					t.Errorf("%s: expected ALLOW, got DENY", tt.desc)
				} else {
					t.Errorf("%s: expected DENY, got ALLOW", tt.desc)
				}
			} else {
				if tt.wantAllow {
					t.Logf("✓ %s", tt.desc)
				} else {
					t.Logf("✓ BLOCKED: %s", tt.desc)
				}
			}
		})
	}
}

func TestDMZBrokerAgent(t *testing.T) {
	policyPath := filepath.Join("policies", "dmz-broker-agent.yaml")
	compiled, agentType := loadPolicy(t, policyPath)

	config := router.DefaultPolicyConfig()
	config.Mode = policy.Enforcing
	r := router.NewToolRouter(config)
	r.LoadPolicy(agentType, compiled)

	ctx := context.Background()

	tests := []struct {
		name      string
		tool      string
		wantAllow bool
		desc      string
	}{
		{"historian_read", "historian.read", true, "DMZ CAN read from operations historian"},
		{"data_relay", "data.relay", true, "DMZ CAN relay data to enterprise"},
		{"protocol_translate", "protocol.translate", true, "DMZ CAN translate protocols"},
		{"historian_write", "historian.write", false, "DMZ CANNOT write to OT historian"},
		{"plc_read", "plc.read", false, "DMZ has NO direct PLC access"},
		{"plc_write", "plc.write", false, "DMZ has NO direct PLC access"},
		{"hmi_read", "hmi.read", false, "DMZ CANNOT access Control Zone"},
		{"file_write", "file.write", false, "DMZ CANNOT store data locally"},
		{"internet_fetch", "internet.fetch", false, "DMZ is isolated - no internet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &router.ExecuteRequest{
				ToolName:   tt.tool,
				Parameters: map[string]interface{}{},
				Metadata: router.RequestMetadata{
					AgentType: agentType,
					SandboxID: "sandbox-dmz-001",
				},
			}

			_, err := r.Execute(ctx, req)
			allowed := (err == nil)

			if allowed != tt.wantAllow {
				if tt.wantAllow {
					t.Errorf("%s: expected ALLOW, got DENY", tt.desc)
				} else {
					t.Errorf("%s: expected DENY, got ALLOW", tt.desc)
				}
			} else {
				if tt.wantAllow {
					t.Logf("✓ %s", tt.desc)
				} else {
					t.Logf("✓ BLOCKED: %s", tt.desc)
				}
			}
		})
	}
}

func TestCrossZoneIsolation(t *testing.T) {
	// Load all three zone policies
	controlPolicy, _ := loadPolicy(t, filepath.Join("policies", "control-zone-agent.yaml"))
	enterprisePolicy, _ := loadPolicy(t, filepath.Join("policies", "enterprise-zone-agent.yaml"))
	dmzPolicy, _ := loadPolicy(t, filepath.Join("policies", "dmz-broker-agent.yaml"))

	config := router.DefaultPolicyConfig()
	config.Mode = policy.Enforcing
	r := router.NewToolRouter(config)

	r.LoadPolicy("control-zone-agent", controlPolicy)
	r.LoadPolicy("enterprise-zone-agent", enterprisePolicy)
	r.LoadPolicy("dmz-broker-agent", dmzPolicy)

	ctx := context.Background()

	t.Run("enterprise_cannot_reach_plc", func(t *testing.T) {
		req := &router.ExecuteRequest{
			ToolName:   "plc.write",
			Parameters: map[string]interface{}{"address": "40001", "value": 999},
			Metadata: router.RequestMetadata{
				AgentType: "enterprise-zone-agent",
				SandboxID: "sandbox-enterprise",
			},
		}

		_, err := r.Execute(ctx, req)
		if err == nil {
			t.Error("CRITICAL: Enterprise agent was able to write to PLC!")
		} else {
			t.Log("✓ Enterprise zone properly isolated from PLCs")
		}
	})

	t.Run("control_cannot_reach_enterprise", func(t *testing.T) {
		req := &router.ExecuteRequest{
			ToolName:   "enterprise.query",
			Parameters: map[string]interface{}{},
			Metadata: router.RequestMetadata{
				AgentType: "control-zone-agent",
				SandboxID: "sandbox-control",
			},
		}

		_, err := r.Execute(ctx, req)
		if err == nil {
			t.Error("Control agent should not have direct enterprise access")
		} else {
			t.Log("✓ Control zone properly isolated from enterprise")
		}
	})

	t.Run("dmz_is_conduit_only", func(t *testing.T) {
		// DMZ can read from operations
		readReq := &router.ExecuteRequest{
			ToolName:   "historian.read",
			Parameters: map[string]interface{}{},
			Metadata: router.RequestMetadata{
				AgentType: "dmz-broker-agent",
				SandboxID: "sandbox-dmz",
			},
		}
		_, err := r.Execute(ctx, readReq)
		if err != nil {
			t.Errorf("DMZ should be able to read historian: %v", err)
		}

		// DMZ cannot write to operations
		writeReq := &router.ExecuteRequest{
			ToolName:   "historian.write",
			Parameters: map[string]interface{}{},
			Metadata: router.RequestMetadata{
				AgentType: "dmz-broker-agent",
				SandboxID: "sandbox-dmz",
			},
		}
		_, err = r.Execute(ctx, writeReq)
		if err == nil {
			t.Error("DMZ should NOT be able to write to historian")
		} else {
			t.Log("✓ DMZ is read-only conduit as expected")
		}
	})
}
