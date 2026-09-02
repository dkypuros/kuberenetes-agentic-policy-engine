// Command policy-engine runs the agentic policy engine as a standalone service.
//
// It exposes an HTTP/JSON API for tool-invocation authorization and, when
// running in Kubernetes, syncs AgentPolicy CRDs into the embedded engine via
// the controller-runtime controller.
//
// Endpoints:
//
//	POST /v1/execute  {"tool": "...", "parameters": {...},
//	                   "metadata": {"agentType": "...", "sandboxId": "...", "tenantId": "..."}}
//	                  -> {"decision": "allow|deny", "reason": "...", "evaluation_ns": N}
//	GET  /healthz     -> 200 once the engine is up
//
// Environment:
//
//	LISTEN_ADDR         address for the HTTP API (default ":8900")
//	ENFORCEMENT_MODE    "enforcing" (default) or "permissive"
//	USE_OPA             "true" to evaluate via OPA/Rego instead of the fast path
//	ENABLE_CONTROLLER   "true" (default) to watch AgentPolicy CRDs in-cluster
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golden-agent/golden-agent/pkg/policy"
	"github.com/golden-agent/golden-agent/pkg/router"
)

type executeRequest struct {
	Tool       string                 `json:"tool"`
	Parameters map[string]interface{} `json:"parameters"`
	Metadata   struct {
		AgentType string `json:"agentType"`
		SandboxID string `json:"sandboxId"`
		TenantID  string `json:"tenantId"`
		SessionID string `json:"sessionId"`
		MTSLabel  string `json:"mtsLabel"`
	} `json:"metadata"`
}

type executeResponse struct {
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	EvaluationNs int64  `json:"evaluation_ns"`
}

func envBool(name string, def bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	return v == "true" || v == "1"
}

func main() {
	cfg := router.DefaultPolicyConfig()
	cfg.Mode = policy.Enforcing
	if os.Getenv("ENFORCEMENT_MODE") == "permissive" {
		cfg.Mode = policy.Permissive
	}
	cfg.UseOPA = envBool("USE_OPA", false)
	cfg.EnableController = envBool("ENABLE_CONTROLLER", true)

	integration := router.NewRouterPolicyIntegration(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.EnableController {
		if err := integration.StartController(ctx); err != nil {
			log.Printf("WARNING: CRD controller not started: %v (continuing with pre-loaded policies only)", err)
		} else {
			log.Printf("AgentPolicy CRD controller started")
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := integration.HealthCheck(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req executeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		if req.Tool == "" || req.Metadata.AgentType == "" {
			http.Error(w, "tool and metadata.agentType are required", http.StatusBadRequest)
			return
		}

		meta := router.RequestMetadata{
			AgentType: req.Metadata.AgentType,
			SandboxID: req.Metadata.SandboxID,
			TenantID:  req.Metadata.TenantID,
			SessionID: req.Metadata.SessionID,
			MTSLabel:  req.Metadata.MTSLabel,
		}

		start := time.Now()
		decision, err := integration.Evaluate(r.Context(), meta, req.Tool, req.Parameters)
		elapsed := time.Since(start).Nanoseconds()

		if err != nil {
			// Fail closed on evaluation errors.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(executeResponse{
				Decision:     "deny",
				Reason:       fmt.Sprintf("policy evaluation error: %v", err),
				EvaluationNs: elapsed,
			})
			return
		}

		resp := executeResponse{EvaluationNs: elapsed}
		w.Header().Set("Content-Type", "application/json")
		if decision == policy.Deny {
			resp.Decision = "deny"
			resp.Reason = fmt.Sprintf("tool %q denied by policy for agent type %q", req.Tool, meta.AgentType)
			w.WriteHeader(http.StatusForbidden)
		} else {
			resp.Decision = "allow"
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(resp)
	})

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8900"
	}

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("policy engine listening on %s (mode=%s opa=%v controller=%v)",
		addr, integration.Mode(), cfg.UseOPA, cfg.EnableController)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
