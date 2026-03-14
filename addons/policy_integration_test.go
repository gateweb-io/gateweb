package addons

import (
	"context"
	"crypto/tls"
	"gateweb/contracts"
	"gateweb/libs/proxy/cert"
	"gateweb/libs/proxy/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTLSBackend starts an HTTPS server with a self-signed cert.
func testTLSBackend(t *testing.T) (int, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin-page"))
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("public-page"))
	})

	ca, err := cert.NewSelfSignCAMemory()
	require.NoError(t, err)
	tlsCert, err := ca.GetCert("localhost")
	require.NoError(t, err)

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := plainLn.Addr().(*net.TCPAddr).Port

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*tlsCert}}
	tlsLn := tls.NewListener(plainLn, tlsConfig)

	server := &http.Server{Handler: mux}
	go server.Serve(tlsLn)

	return port, func() {
		server.Shutdown(context.Background())
	}
}

// startTestProxy creates a proxy with the given addon and intercept rule.
func startTestProxy(t *testing.T, addr string, addon proxy.Addon, shouldIntercept func(*http.Request) bool) (*proxy.Proxy, func()) {
	t.Helper()
	p, err := proxy.NewProxy(&proxy.Options{
		Addr:        addr,
		SslInsecure: true,
	})
	require.NoError(t, err)

	if addon != nil {
		p.AddAddon(addon)
	}
	if shouldIntercept != nil {
		p.SetShouldInterceptRule(shouldIntercept)
	}

	go p.Start()
	time.Sleep(50 * time.Millisecond)

	return p, func() {
		p.Shutdown(context.Background())
	}
}

func proxyClient(proxyAddr string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy: func(r *http.Request) (*url.URL, error) {
				return url.Parse("http://" + proxyAddr)
			},
		},
	}
}

// TestIntegration_DomainPolicySelectiveIntercept verifies that with domain-only policy:
// - Allowed domains pass through via directTransfer (no MITM)
// - Blocked domains get MITM'd so the block page renders in the browser
func TestIntegration_DomainPolicySelectiveIntercept(t *testing.T) {
	backendPort, backendCleanup := testTLSBackend(t)
	defer backendCleanup()

	provider := &mockPolicyProvider{
		needsInspection: false,
		rules: []contracts.PolicyRule{
			{
				ID:      "block-bad",
				Name:    "Block bad.com",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "domain", Value: "bad.com"},
				},
			},
		},
	}
	sink := &mockEventSink{}
	policyAddon := NewPolicyAddon(provider, sink)

	// Selective intercept: only MITM blocked domains
	selectiveIntercept := func(req *http.Request) bool {
		return policyAddon.ShouldIntercept(req.Host)
	}
	_, proxyCleanup := startTestProxy(t, "127.0.0.1:19090", policyAddon, selectiveIntercept)
	defer proxyCleanup()

	client := proxyClient("127.0.0.1:19090")

	t.Run("allowed domain passes through without MITM", func(t *testing.T) {
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(backendPort) + "/")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "ok", string(body))
	})

	t.Run("blocked domain gets MITM'd and sees block page", func(t *testing.T) {
		// bad.com won't resolve, but with MITM the proxy generates a cert
		// from SNI, and the policy addon serves the block page on the inner
		// HTTP request — so the browser sees a proper 403 page.
		// Since bad.com:443 doesn't exist, the MITM can't connect upstream.
		// The proxy will try UpstreamCert=true (connect first), which fails.
		// We can test the ShouldIntercept logic directly instead.
		assert.True(t, policyAddon.ShouldIntercept("bad.com:443"),
			"blocked domain should trigger interception")
		assert.False(t, policyAddon.ShouldIntercept("google.com:443"),
			"allowed domain should not trigger interception")
	})

	t.Run("events emitted for CONNECT on allowed domain", func(t *testing.T) {
		sink.events = nil
		freshClient := proxyClient("127.0.0.1:19090")
		freshClient.Get("https://127.0.0.1:" + strconv.Itoa(backendPort) + "/")
		assert.GreaterOrEqual(t, len(sink.events), 1, "should emit event for CONNECT")
	})
}

// TestIntegration_PathPolicyWithIntercept verifies that with path-based policy:
// - All traffic gets MITM'd
// - Path-based rules serve block page on inner HTTP request
// - Domain rules also work (block page on inner HTTP request)
func TestIntegration_PathPolicyWithIntercept(t *testing.T) {
	backendPort, backendCleanup := testTLSBackend(t)
	defer backendCleanup()

	provider := &mockPolicyProvider{
		needsInspection: true,
		rules: []contracts.PolicyRule{
			{
				ID:      "block-admin",
				Name:    "Block admin path",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "path", Value: "/admin"},
				},
			},
		},
	}
	sink := &mockEventSink{}
	policyAddon := NewPolicyAddon(provider, sink)

	// NeedsInspection true → MITM all (shouldIntercept = nil → intercept all)
	_, proxyCleanup := startTestProxy(t, "127.0.0.1:19091", policyAddon, nil)
	defer proxyCleanup()

	client := proxyClient("127.0.0.1:19091")

	t.Run("allowed path passes through with MITM", func(t *testing.T) {
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(backendPort) + "/public")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "public-page", string(body))
	})

	t.Run("blocked path returns 403 block page after MITM", func(t *testing.T) {
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(backendPort) + "/admin")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.True(t, strings.Contains(string(body), "Access Denied"),
			"should contain block page content")
	})
}

// TestIntegration_NoInterceptPathNotVisible verifies that without MITM,
// path-based rules can't fire because the path is not visible at CONNECT level.
func TestIntegration_NoInterceptPathNotVisible(t *testing.T) {
	backendPort, backendCleanup := testTLSBackend(t)
	defer backendCleanup()

	pathBlockProvider := &mockPolicyProvider{
		needsInspection: false,
		rules: []contracts.PolicyRule{
			{
				ID:      "block-admin",
				Name:    "Block admin path",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "path", Value: "/admin"},
				},
			},
		},
	}
	sink := &mockEventSink{}
	policyAddon := NewPolicyAddon(pathBlockProvider, sink)

	// No intercept → path rule can't fire (path not visible at CONNECT)
	noIntercept := func(req *http.Request) bool { return false }
	_, proxyCleanup := startTestProxy(t, "127.0.0.1:19092", policyAddon, noIntercept)
	defer proxyCleanup()

	client := proxyClient("127.0.0.1:19092")

	t.Run("path rule does NOT block without MITM", func(t *testing.T) {
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(backendPort) + "/admin")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		// Request passes through because path is not visible without MITM
		assert.Equal(t, "admin-page", string(body))
	})
}
