package addons

import (
	"encoding/json"
	"gateweb/libs/proxy/proxy"
	"net/http"
	"sync"
	"time"
)

const defaultMaxSessions = 1000

// Session represents a completed HTTP request/response pair.
type Session struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Method         string    `json:"method"`
	Host           string    `json:"host"`
	Path           string    `json:"path"`
	Proto          string    `json:"proto"`
	TLS            bool      `json:"tls"`
	RequestSize    int       `json:"request_size"`
	ResponseStatus int       `json:"response_status"`
	ResponseSize   int       `json:"response_size"`
	DurationMs     int64     `json:"duration_ms"`
	ContentType    string    `json:"content_type,omitempty"`
	PolicyAction   string    `json:"policy_action,omitempty"`
	PolicyRule     string    `json:"policy_rule,omitempty"`
}

// DomainGroup groups sessions by domain.
type DomainGroup struct {
	Domain       string    `json:"domain"`
	TLS          bool      `json:"tls"`
	RequestCount int       `json:"request_count"`
	BlockedCount int       `json:"blocked_count"`
	TotalBytes   int64     `json:"total_bytes"`
	LastSeen     time.Time `json:"last_seen"`
	Sessions     []Session `json:"sessions"`
}

// SessionStore captures proxy sessions in a ring buffer.
type SessionStore struct {
	proxy.BaseAddon
	mu       sync.RWMutex
	sessions []Session
	max      int
	starts   map[string]time.Time
	startsMu sync.Mutex
}

// NewSessionStore creates a session store with the given max capacity.
func NewSessionStore(max int) *SessionStore {
	if max <= 0 {
		max = defaultMaxSessions
	}
	return &SessionStore{
		sessions: make([]Session, 0, max),
		max:      max,
		starts:   make(map[string]time.Time),
	}
}

func (s *SessionStore) Requestheaders(f *proxy.Flow) {
	start := time.Now()
	s.startsMu.Lock()
	s.starts[f.Id.String()] = start
	s.startsMu.Unlock()

	// Skip CONNECT — these are TLS tunnel handshakes, not real requests.
	if f.Request.Method == "CONNECT" {
		// Clean up the start time entry since we won't process this flow.
		go func() {
			<-f.Done()
			s.startsMu.Lock()
			delete(s.starts, f.Id.String())
			s.startsMu.Unlock()
		}()
		return
	}

	// Wait for the flow to complete (works for both proxied and blocked requests).
	go func() {
		<-f.Done()

		s.startsMu.Lock()
		st, ok := s.starts[f.Id.String()]
		delete(s.starts, f.Id.String())
		s.startsMu.Unlock()
		if !ok {
			st = start
		}

		session := Session{
			ID:         f.Id.String(),
			Timestamp:  st,
			Method:     f.Request.Method,
			Host:       f.Request.URL.Hostname(),
			Path:       f.Request.URL.Path,
			Proto:      f.Request.Proto,
			TLS:        f.ConnContext.ClientConn.Tls,
			DurationMs: time.Since(st).Milliseconds(),
		}

		if f.Request.Body != nil {
			session.RequestSize = len(f.Request.Body)
		}

		if f.Response != nil {
			session.ResponseStatus = f.Response.StatusCode
			if f.Response.Body != nil {
				session.ResponseSize = len(f.Response.Body)
			}
			session.ContentType = f.Response.Header.Get("Content-Type")

			// Detect policy-blocked requests.
			if f.Response.Header.Get("X-Policy-Rule") != "" {
				session.PolicyAction = "block"
				session.PolicyRule = f.Response.Header.Get("X-Policy-Rule-Name")
			}
		}

		s.mu.Lock()
		if len(s.sessions) >= s.max {
			drop := s.max / 4
			s.sessions = s.sessions[drop:]
		}
		s.sessions = append(s.sessions, session)
		s.mu.Unlock()
	}()
}

// Sessions returns all captured sessions (newest last).
func (s *SessionStore) Sessions() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, len(s.sessions))
	copy(out, s.sessions)
	return out
}

// Domains returns sessions grouped by domain.
func (s *SessionStore) Domains() []DomainGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make(map[string]*DomainGroup)
	for _, sess := range s.sessions {
		g, ok := groups[sess.Host]
		if !ok {
			g = &DomainGroup{
				Domain:   sess.Host,
				TLS:      sess.TLS,
				Sessions: make([]Session, 0),
			}
			groups[sess.Host] = g
		}
		g.RequestCount++
		if sess.PolicyAction == "block" {
			g.BlockedCount++
		}
		g.TotalBytes += int64(sess.ResponseSize)
		if sess.Timestamp.After(g.LastSeen) {
			g.LastSeen = sess.Timestamp
		}
		g.Sessions = append(g.Sessions, sess)
	}

	result := make([]DomainGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	return result
}

// Clear removes all sessions.
func (s *SessionStore) Clear() {
	s.mu.Lock()
	s.sessions = s.sessions[:0]
	s.mu.Unlock()
}

// HandleSessions returns an http.HandlerFunc for the /api/sessions endpoint.
func (s *SessionStore) HandleSessions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Sessions())
	}
}

// HandleDomains returns an http.HandlerFunc for the /api/domains endpoint.
func (s *SessionStore) HandleDomains() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Domains())
	}
}

// HandleClear returns an http.HandlerFunc for POST /api/sessions/clear.
func (s *SessionStore) HandleClear() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.Clear()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
	}
}
