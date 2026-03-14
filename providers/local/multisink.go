package local

import (
	"context"
	"gateweb/contracts"
)

// MultiSink fans out events to multiple sinks.
type MultiSink struct {
	sinks []contracts.EventSink
}

// NewMultiSink creates a sink that writes to all provided sinks.
func NewMultiSink(sinks ...contracts.EventSink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (m *MultiSink) Emit(ctx context.Context, event *contracts.Event) error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Emit(ctx, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiSink) EmitBatch(ctx context.Context, events []*contracts.Event) error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.EmitBatch(ctx, events); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiSink) Close() error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
