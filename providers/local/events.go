package local

import (
	"bufio"
	"context"
	"encoding/json"
	"gateweb/contracts"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultFlushInterval = 1 * time.Second
	defaultBufSize       = 64 * 1024 // 64KB write buffer
)

// AccessLog writes events as JSON lines to one or more sinks.
// Follows Envoy's access log model:
//   - Structured JSON to stdout by default
//   - Optional file sink (operator handles rotation via logrotate)
//   - Buffered writes with periodic flush
//   - Configurable event filtering
type AccessLog struct {
	mu      sync.Mutex
	writers []*bufio.Writer
	closers []io.Closer
	filter  contracts.EventFilter
	seq     atomic.Uint64
	done    chan struct{}
}

// AccessLogOption configures the AccessLog.
type AccessLogOption func(*AccessLog)

// WithFile adds a file sink. The file is opened in append mode.
// Rotation is handled externally (logrotate, etc.).
func WithFile(path string) AccessLogOption {
	return func(a *AccessLog) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[access_log] warning: could not create directory for %s: %v\n", path, err)
			return
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[access_log] warning: could not open %s: %v\n", path, err)
			return
		}
		a.writers = append(a.writers, bufio.NewWriterSize(f, defaultBufSize))
		a.closers = append(a.closers, f)
	}
}

// WithStdout adds stdout as a sink (this is the default if no sinks are added).
func WithStdout() AccessLogOption {
	return func(a *AccessLog) {
		a.writers = append(a.writers, bufio.NewWriterSize(os.Stdout, defaultBufSize))
	}
}

// WithFilter sets an event filter. Only events passing the filter are logged.
func WithFilter(f contracts.EventFilter) AccessLogOption {
	return func(a *AccessLog) {
		a.filter = f
	}
}

// NewAccessLog creates a new access log.
// Events are only written to explicitly configured sinks (file, stdout).
// If no sinks are configured, events are silently dropped (the in-memory
// EventStore still captures them for the dashboard).
func NewAccessLog(opts ...AccessLogOption) *AccessLog {
	a := &AccessLog{
		filter: contracts.FilterAll,
		done:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(a)
	}
	if len(a.writers) > 0 {
		go a.flushLoop()
	}
	return a
}

// flushLoop periodically flushes all buffered writers.
func (a *AccessLog) flushLoop() {
	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.flush()
		case <-a.done:
			return
		}
	}
}

func (a *AccessLog) flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, w := range a.writers {
		w.Flush()
	}
}

// Emit writes a single event to all sinks.
func (a *AccessLog) Emit(_ context.Context, event *contracts.Event) error {
	if !a.filter(event) {
		return nil
	}

	// Auto-assign ID if empty.
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d-%d", event.Timestamp.UnixMilli(), a.seq.Add(1))
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	for _, w := range a.writers {
		w.Write(data)
	}
	return nil
}

// EmitBatch writes multiple events.
func (a *AccessLog) EmitBatch(ctx context.Context, events []*contracts.Event) error {
	for _, e := range events {
		if err := a.Emit(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes all buffers and closes file sinks.
func (a *AccessLog) Close() error {
	close(a.done)
	a.flush()
	for _, c := range a.closers {
		c.Close()
	}
	return nil
}

// --- Backwards-compatible aliases ---

// StdoutEventSinkOption is kept for compatibility.
type StdoutEventSinkOption = AccessLogOption

// WithEventFile is an alias for WithFile.
func WithEventFile(path string) AccessLogOption { return WithFile(path) }

// NewStdoutEventSink creates an AccessLog with stdout + optional file.
// Kept for compatibility with existing code.
func NewStdoutEventSink(opts ...AccessLogOption) *AccessLog {
	return NewAccessLog(opts...)
}
