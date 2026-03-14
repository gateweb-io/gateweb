package contracts

import "context"

// EventSink receives proxy events for logging, analytics, or streaming.
// Design follows Envoy's access log model: structured JSON to stdout,
// with optional file sinks and filtering.
type EventSink interface {
	// Emit sends a single event.
	Emit(ctx context.Context, event *Event) error

	// EmitBatch sends multiple events (for buffered flush).
	EmitBatch(ctx context.Context, events []*Event) error

	// Close flushes pending events and releases resources.
	Close() error
}

// EventFilter decides whether an event should be logged.
// Return true to log the event, false to drop it.
type EventFilter func(event *Event) bool

// FilterAll logs every event (default).
func FilterAll(_ *Event) bool { return true }

// FilterBlocked logs only blocked requests.
func FilterBlocked(e *Event) bool { return e.PolicyAction == ActionBlock }

// FilterDecisions logs only requests where a policy rule matched.
func FilterDecisions(e *Event) bool { return e.PolicyRuleID != "" }

// FilterNot inverts a filter.
func FilterNot(f EventFilter) EventFilter {
	return func(e *Event) bool { return !f(e) }
}

// FilterAny returns true if any of the filters match.
func FilterAny(filters ...EventFilter) EventFilter {
	return func(e *Event) bool {
		for _, f := range filters {
			if f(e) {
				return true
			}
		}
		return false
	}
}
