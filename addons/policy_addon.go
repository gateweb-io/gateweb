package addons

import (
	"context"
	"gateweb/contracts"
	"gateweb/libs/proxy/proxy"
	"gateweb/urldb"
	"fmt"
	"net"
	"net/http"
	"time"
)

// CategorySource provides access to the current URL categorizer.
// This interface allows dynamic sources (e.g., remote loaders that poll
// for updates) to be used alongside static categorizers.
type CategorySource interface {
	Categorizer() *urldb.Categorizer
}

// staticCategorySource wraps a fixed categorizer.
type staticCategorySource struct {
	c *urldb.Categorizer
}

func (s *staticCategorySource) Categorizer() *urldb.Categorizer { return s.c }

// StaticCategorySource wraps a fixed categorizer as a CategorySource.
func StaticCategorySource(c *urldb.Categorizer) CategorySource {
	return &staticCategorySource{c: c}
}

// PolicyAddon evaluates each request against a PolicyProvider and blocks
// requests that violate policy rules.
type PolicyAddon struct {
	proxy.BaseAddon
	provider       contracts.PolicyProvider
	eventSink      contracts.EventSink
	categorySource CategorySource
	userID         string
	tenantID       string
}

// PolicyAddonOption configures a PolicyAddon.
type PolicyAddonOption func(*PolicyAddon)

// WithCategorizer sets a static URL categorizer for populating request categories.
func WithCategorizer(c *urldb.Categorizer) PolicyAddonOption {
	return func(a *PolicyAddon) {
		a.categorySource = &staticCategorySource{c: c}
	}
}

// WithCategorySource sets a dynamic category source (e.g., RemoteCategoryLoader).
func WithCategorySource(src CategorySource) PolicyAddonOption {
	return func(a *PolicyAddon) {
		a.categorySource = src
	}
}

// WithIdentity sets the user and tenant IDs for event attribution.
func WithIdentity(userID, tenantID string) PolicyAddonOption {
	return func(a *PolicyAddon) {
		a.userID = userID
		a.tenantID = tenantID
	}
}

// NewPolicyAddon creates an addon that enforces policy on every request.
// eventSink is optional — if nil, policy events are not emitted.
func NewPolicyAddon(provider contracts.PolicyProvider, eventSink contracts.EventSink, opts ...PolicyAddonOption) *PolicyAddon {
	a := &PolicyAddon{
		provider:  provider,
		eventSink: eventSink,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// ShouldIntercept returns true if the given host would be blocked by policy.
// Used as the shouldIntercept callback so that blocked domains get MITM'd
// (allowing the block page to render) while allowed domains pass through directly.
func (a *PolicyAddon) ShouldIntercept(host string) bool {
	if a.provider == nil {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	req := a.buildRequest(host, "")
	decision, err := a.provider.Evaluate(context.Background(), req)
	if err != nil {
		return false
	}
	return decision.Action == contracts.ActionBlock
}

// buildRequest creates a PolicyRequest with category enrichment.
func (a *PolicyAddon) buildRequest(host, path string) contracts.PolicyRequest {
	req := contracts.PolicyRequest{Host: host, Path: path}
	if a.categorySource != nil {
		if cat := a.categorySource.Categorizer(); cat != nil {
			if cats := cat.Lookup(host, path); len(cats) > 0 {
				req.Categories = cats
				req.Category = cats[0]
			}
		}
	}
	return req
}

func (a *PolicyAddon) Requestheaders(flow *proxy.Flow) {
	if a.provider == nil {
		return
	}

	host := flow.Request.URL.Hostname()
	path := flow.Request.URL.Path

	isConnect := flow.Request.Method == "CONNECT"

	// For CONNECT (tunnel setup), extract host from host:port target.
	// Don't block here — let shouldIntercept decide whether to MITM.
	// Blocking on the inner MITM'd request allows the browser to render
	// the block page instead of showing ERR_TUNNEL_CONNECTION_FAILED.
	if isConnect {
		host = flow.Request.URL.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		path = ""
	}

	req := a.buildRequest(host, path)
	req.Method = flow.Request.Method

	decision, err := a.provider.Evaluate(context.Background(), req)
	if err != nil {
		fmt.Printf("[policy] evaluation error for %s: %v\n", flow.Request.URL.Host, err)
		return
	}

	// Only block on inner HTTP requests (after MITM), not on CONNECT.
	// On CONNECT, blocking causes ERR_TUNNEL_CONNECTION_FAILED in the browser.
	// Instead, shouldIntercept selectively MITMs blocked domains so the
	// block page can be served as a proper HTTP response.
	if decision.Action == contracts.ActionBlock && !isConnect {
		reason := decision.Reason
		if req.Category != "" {
			reason = fmt.Sprintf("Blocked due to category: %s", req.Category)
		}
		flow.Response = &proxy.Response{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type":       {"text/html; charset=utf-8"},
				"X-Policy-Rule":      {decision.RuleID},
				"X-Policy-Rule-Name": {decision.RuleName},
			},
			Body: renderBlockPage(host, decision.RuleName, reason),
		}
	}

	// Emit policy event for all traffic
	if a.eventSink != nil {
		event := &contracts.Event{
			Timestamp:     time.Now(),
			UserID:        a.userID,
			TenantID:      a.tenantID,
			RequestMethod: flow.Request.Method,
			RequestHost:   host,
			RequestPath:   flow.Request.URL.Path,
			PolicyRuleID:  decision.RuleID,
			PolicyAction:  decision.Action,
			Category:      req.Category,
			Categories:    req.Categories,
		}
		if err := a.eventSink.Emit(context.Background(), event); err != nil {
			fmt.Printf("[policy] failed to emit event: %v\n", err)
		}
	}
}
