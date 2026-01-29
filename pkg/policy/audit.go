// Package policy implements audit logging for agent policy decisions.
// Follows the SELinux AVC (Access Vector Cache) denial log pattern.
package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditEmitter manages audit event emission to multiple sinks.
// It provides buffering and concurrent-safe logging.
type AuditEmitter struct {
	sinks []AuditSink
	mu    sync.RWMutex

	// Stats for monitoring
	totalEvents    uint64
	allowEvents    uint64
	denyEvents     uint64
	cachedEvents   uint64
	statsMu        sync.RWMutex
}

// NewAuditEmitter creates an emitter with the given sinks.
// If no sinks are provided, events are silently dropped.
func NewAuditEmitter(sinks ...AuditSink) *AuditEmitter {
	return &AuditEmitter{
		sinks: sinks,
	}
}

// AddSink adds a new audit sink.
func (e *AuditEmitter) AddSink(sink AuditSink) {
	e.mu.Lock()
	e.sinks = append(e.sinks, sink)
	e.mu.Unlock()
}

// Log sends an audit event to all registered sinks.
// Implements the AuditSink interface.
func (e *AuditEmitter) Log(event *AuditEvent) {
	// Update stats
	e.statsMu.Lock()
	e.totalEvents++
	if event.Decision == Allow {
		e.allowEvents++
	} else {
		e.denyEvents++
	}
	if event.Cached {
		e.cachedEvents++
	}
	e.statsMu.Unlock()

	// Send to all sinks
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, sink := range e.sinks {
		sink.Log(event)
	}
}

// Stats returns audit statistics.
func (e *AuditEmitter) Stats() (total, allow, deny, cached uint64) {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()
	return e.totalEvents, e.allowEvents, e.denyEvents, e.cachedEvents
}

// --- Concrete AuditSink implementations ---

// StdoutAuditSink logs events to stdout in SELinux AVC format.
// This is useful for development and debugging.
type StdoutAuditSink struct {
	// OnlyDenials filters to only log deny events (like ausearch --message AVC)
	OnlyDenials bool
}

// NewStdoutAuditSink creates a sink that logs to stdout.
func NewStdoutAuditSink(onlyDenials bool) *StdoutAuditSink {
	return &StdoutAuditSink{OnlyDenials: onlyDenials}
}

// Log writes the event to stdout in AVC-style format.
func (s *StdoutAuditSink) Log(event *AuditEvent) {
	if s.OnlyDenials && event.Decision == Allow {
		return
	}
	fmt.Fprintln(os.Stdout, formatAVC(event))
}

// formatAVC formats an audit event like SELinux AVC logs:
// type=AVC msg=audit(timestamp): avc: denied { tool_call } for tool="file.read" agent="coding-assistant" reason="no permission"
func formatAVC(event *AuditEvent) string {
	action := "granted"
	if event.Decision == Deny {
		action = "denied"
	}

	cached := ""
	if event.Cached {
		cached = " cached=1"
	}

	return fmt.Sprintf(
		"type=AVC msg=audit(%d.%03d:%s): avc: %s { tool_call } for tool=%q agent_type=%q sandbox=%q tenant=%q mts=%q reason=%q%s",
		event.Timestamp.Unix(),
		event.Timestamp.Nanosecond()/1e6, // milliseconds
		event.RequestID,
		action,
		event.Tool,
		event.Agent.AgentType,
		event.Agent.SandboxID,
		event.Agent.TenantID,
		event.Agent.MTSLabel,
		event.Reason,
		cached,
	)
}

// JSONAuditSink logs events as JSON lines to a writer.
// Suitable for structured logging systems (ELK, Splunk, CloudWatch).
type JSONAuditSink struct {
	writer io.Writer
	mu     sync.Mutex

	// OnlyDenials filters to only log deny events
	OnlyDenials bool
}

// JSONAuditEvent is the JSON representation of an audit event.
type JSONAuditEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
	Tool      string `json:"tool"`
	Agent     struct {
		Type      string `json:"type"`
		SandboxID string `json:"sandbox_id"`
		TenantID  string `json:"tenant_id"`
		SessionID string `json:"session_id"`
		MTSLabel  string `json:"mts_label"`
		PolicyRef string `json:"policy_ref"`
	} `json:"agent"`
	Reason string `json:"reason"`
	Cached bool   `json:"cached"`
}

// NewJSONAuditSink creates a sink that writes JSON lines.
func NewJSONAuditSink(w io.Writer, onlyDenials bool) *JSONAuditSink {
	return &JSONAuditSink{
		writer:      w,
		OnlyDenials: onlyDenials,
	}
}

// Log writes the event as a JSON line.
func (s *JSONAuditSink) Log(event *AuditEvent) {
	if s.OnlyDenials && event.Decision == Allow {
		return
	}

	jsonEvent := JSONAuditEvent{
		Type:      "AVC",
		Timestamp: event.Timestamp.Format(time.RFC3339Nano),
		RequestID: event.RequestID,
		Decision:  event.Decision.String(),
		Tool:      event.Tool,
		Reason:    event.Reason,
		Cached:    event.Cached,
	}
	jsonEvent.Agent.Type = event.Agent.AgentType
	jsonEvent.Agent.SandboxID = event.Agent.SandboxID
	jsonEvent.Agent.TenantID = event.Agent.TenantID
	jsonEvent.Agent.SessionID = event.Agent.SessionID
	jsonEvent.Agent.MTSLabel = event.Agent.MTSLabel
	jsonEvent.Agent.PolicyRef = event.Agent.PolicyRef

	data, err := json.Marshal(jsonEvent)
	if err != nil {
		return // Silently drop on marshal error
	}

	s.mu.Lock()
	s.writer.Write(data)
	s.writer.Write([]byte("\n"))
	s.mu.Unlock()
}

// FileAuditSink logs events to a file with rotation support.
type FileAuditSink struct {
	path        string
	file        *os.File
	mu          sync.Mutex
	onlyDenials bool
	format      string // "avc" or "json"
}

// NewFileAuditSink creates a sink that writes to a file.
// Format can be "avc" for SELinux-style or "json" for structured logs.
func NewFileAuditSink(path string, format string, onlyDenials bool) (*FileAuditSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	if format != "avc" && format != "json" {
		format = "avc" // Default to AVC format
	}

	return &FileAuditSink{
		path:        path,
		file:        f,
		onlyDenials: onlyDenials,
		format:      format,
	}, nil
}

// Log writes the event to the file.
func (s *FileAuditSink) Log(event *AuditEvent) {
	if s.onlyDenials && event.Decision == Allow {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.format == "json" {
		jsonEvent := JSONAuditEvent{
			Type:      "AVC",
			Timestamp: event.Timestamp.Format(time.RFC3339Nano),
			RequestID: event.RequestID,
			Decision:  event.Decision.String(),
			Tool:      event.Tool,
			Reason:    event.Reason,
			Cached:    event.Cached,
		}
		jsonEvent.Agent.Type = event.Agent.AgentType
		jsonEvent.Agent.SandboxID = event.Agent.SandboxID
		jsonEvent.Agent.TenantID = event.Agent.TenantID
		jsonEvent.Agent.SessionID = event.Agent.SessionID
		jsonEvent.Agent.MTSLabel = event.Agent.MTSLabel
		jsonEvent.Agent.PolicyRef = event.Agent.PolicyRef

		data, _ := json.Marshal(jsonEvent)
		s.file.Write(data)
		s.file.Write([]byte("\n"))
	} else {
		fmt.Fprintln(s.file, formatAVC(event))
	}
}

// Close closes the file.
func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

// NullAuditSink discards all events (for testing or disabled auditing).
type NullAuditSink struct{}

// Log does nothing.
func (s *NullAuditSink) Log(event *AuditEvent) {}

// ChannelAuditSink sends events to a channel (for async processing).
type ChannelAuditSink struct {
	events chan *AuditEvent
}

// NewChannelAuditSink creates a sink that sends to a buffered channel.
func NewChannelAuditSink(bufferSize int) *ChannelAuditSink {
	return &ChannelAuditSink{
		events: make(chan *AuditEvent, bufferSize),
	}
}

// Log sends the event to the channel, dropping if full.
func (s *ChannelAuditSink) Log(event *AuditEvent) {
	select {
	case s.events <- event:
	default:
		// Channel full, drop event
	}
}

// Events returns the channel for reading events.
func (s *ChannelAuditSink) Events() <-chan *AuditEvent {
	return s.events
}

// Close closes the events channel.
func (s *ChannelAuditSink) Close() {
	close(s.events)
}
