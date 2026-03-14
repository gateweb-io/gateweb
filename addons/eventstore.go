package addons

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"gateweb/contracts"
)

const defaultMaxEvents = 500

// EventStore keeps recent events in memory for the dashboard.
// Implements contracts.EventSink.
type EventStore struct {
	mu     sync.RWMutex
	events []*contracts.Event
	max    int
	seq    uint64
}

// NewEventStore creates an in-memory event store.
func NewEventStore(max int) *EventStore {
	if max <= 0 {
		max = defaultMaxEvents
	}
	return &EventStore{
		events: make([]*contracts.Event, 0, max),
		max:    max,
	}
}

func (s *EventStore) Emit(_ context.Context, event *contracts.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if event.ID == "" {
		s.seq++
		event.ID = fmt.Sprintf("%d-%d", event.Timestamp.UnixMilli(), s.seq)
	}

	if len(s.events) >= s.max {
		drop := s.max / 4
		s.events = s.events[drop:]
	}
	s.events = append(s.events, event)
	return nil
}

func (s *EventStore) EmitBatch(ctx context.Context, events []*contracts.Event) error {
	for _, e := range events {
		if err := s.Emit(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (s *EventStore) Close() error { return nil }

// Events returns all stored events (newest last).
func (s *EventStore) Events() []*contracts.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*contracts.Event, len(s.events))
	copy(out, s.events)
	return out
}

// Clear removes all events.
func (s *EventStore) Clear() {
	s.mu.Lock()
	s.events = s.events[:0]
	s.mu.Unlock()
}

// HandleEvents returns an http.HandlerFunc for /api/events.
// Supports ?filter=blocked and ?host=example.com query params.
func (s *EventStore) HandleEvents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		events := s.Events()

		filterParam := r.URL.Query().Get("filter")
		hostParam := r.URL.Query().Get("host")

		if filterParam != "" || hostParam != "" {
			filtered := make([]*contracts.Event, 0, len(events))
			filters := strings.Split(filterParam, ",")
			for _, e := range events {
				if hostParam != "" && e.RequestHost != hostParam {
					continue
				}
				if filterParam != "" && !matchesEventFilter(e, filters) {
					continue
				}
				filtered = append(filtered, e)
			}
			events = filtered
		}

		json.NewEncoder(w).Encode(events)
	}
}

// HandleEventStats returns summary stats for the events.
func (s *EventStore) HandleEventStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		events := s.Events()

		var blocked, total int
		var since time.Time
		for _, e := range events {
			total++
			if e.PolicyAction == contracts.ActionBlock {
				blocked++
			}
			if since.IsZero() || e.Timestamp.Before(since) {
				since = e.Timestamp
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"total":   total,
			"blocked": blocked,
			"since":   since,
		})
	}
}

// HandleCategoryStats returns category distribution from events.
func (s *EventStore) HandleCategoryStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		events := s.Events()

		counts := make(map[string]int)
		for _, e := range events {
			if len(e.Categories) > 0 {
				for _, c := range e.Categories {
					counts[c]++
				}
			} else {
				counts["uncategorized"]++
			}
		}

		type entry struct {
			Category string `json:"category"`
			Count    int    `json:"count"`
		}
		result := make([]entry, 0, len(counts))
		for cat, cnt := range counts {
			result = append(result, entry{Category: cat, Count: cnt})
		}
		// Sort by count descending.
		sort.Slice(result, func(i, j int) bool {
			return result[i].Count > result[j].Count
		})

		json.NewEncoder(w).Encode(result)
	}
}

func matchesEventFilter(e *contracts.Event, filters []string) bool {
	for _, f := range filters {
		switch strings.TrimSpace(f) {
		case "blocked":
			if e.PolicyAction == contracts.ActionBlock {
				return true
			}
		case "all":
			return true
		}
	}
	return false
}
