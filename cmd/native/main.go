package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"

	"gateweb/addons"
	"gateweb/contracts"
	"gateweb/libs/proxy/proxy"
	"gateweb/providers/local"
	"gateweb/urldb"
	"gateweb/urldb/ut1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "Proxy listen address")
	caPath := flag.String("ca-path", "", "CA certificate storage path (default: ~/.gateweb)")
	controlPort := flag.String("control-port", "8765", "Control HTTP server port for health/shutdown")
	policyPath := flag.String("policy", "", "Path to policy.yaml file")
	eventFile := flag.String("event-file", "", "Path to write JSON-lines access log")
	eventFilter := flag.String("event-filter", "all", "Event filter: all, blocked, decisions")
	urldbPath := flag.String("urldb-path", "", "Path to URL categorization database (JSON)")
	enableUrldb := flag.Bool("urldb", false, "Enable URL categorization (auto-downloads UT1 on first run)")
	urldbUpdate := flag.Bool("urldb-update", false, "Force re-download UT1 URL database")
	quiet := flag.Bool("quiet", false, "Suppress proxy connection logs (only show errors and startup info)")
	verbose := flag.Bool("verbose", false, "Enable debug-level logging")
	flag.Parse()

	// Configure log level for the proxy library.
	switch {
	case *quiet:
		log.SetLevel(log.WarnLevel)
	case *verbose:
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	// Build proxy options
	opts := &proxy.Options{
		Addr:              *addr,
		StreamLargeBodies: 1024 * 1024 * 5, // 5MB
	}
	if *caPath != "" {
		opts.CaRootPath = *caPath
	}

	// Create proxy
	p, err := proxy.NewProxy(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create proxy: %v\n", err)
		os.Exit(1)
	}

	// Build access log (file/stdout sink)
	var logOpts []local.AccessLogOption
	if *eventFile != "" {
		logOpts = append(logOpts, local.WithFile(*eventFile))
	}
	var filter contracts.EventFilter
	switch *eventFilter {
	case "blocked":
		filter = contracts.FilterBlocked
	case "decisions":
		filter = contracts.FilterDecisions
	default:
		filter = contracts.FilterAll
	}
	logOpts = append(logOpts, local.WithFilter(filter))
	accessLog := local.NewAccessLog(logOpts...)
	defer accessLog.Close()

	// In-memory event store for dashboard
	eventStore := addons.NewEventStore(500)

	// MultiSink: events go to both file/stdout AND dashboard
	eventSink := local.NewMultiSink(accessLog, eventStore)

	// URL categorization database.
	var policyOpts []addons.PolicyAddonOption
	var catSource addons.CategorySource
	if *enableUrldb || *urldbPath != "" || *urldbUpdate {
		dbPath := *urldbPath
		if dbPath == "" {
			dbPath = defaultUrldbPath()
		}

		// Download/update if requested or if the file doesn't exist.
		if *urldbUpdate || !fileExists(dbPath) {
			fmt.Fprintf(os.Stderr, "Downloading UT1 URL database... ")
			if err := downloadUrldb(dbPath); err != nil {
				fmt.Fprintf(os.Stderr, "failed: %v\n", err)
				fmt.Fprintln(os.Stderr, "Continuing without URL categorization. Use --urldb-update to retry.")
			} else {
				fmt.Fprintln(os.Stderr, "done")
			}
		}

		if fileExists(dbPath) {
			categorizer, err := urldb.NewCategorizer(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load urldb: %v\n", err)
				os.Exit(1)
			}
			defer categorizer.Close()
			policyOpts = append(policyOpts, addons.WithCategorizer(categorizer))
			catSource = addons.StaticCategorySource(categorizer)
		}
	}

	// Add session store for dashboard (must be before policy addon
	// so it captures blocked requests via f.Done()).
	sessions := addons.NewSessionStore(1000)
	p.AddAddon(sessions)

	// Local policy file
	if *policyPath != "" {
		policyProvider, err := local.NewYAMLPolicyProvider(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
			os.Exit(1)
		}
		policyAddon := addons.NewPolicyAddon(policyProvider, eventSink, policyOpts...)
		p.AddAddon(policyAddon)

		if policyProvider.NeedsInspection() {
			fmt.Printf("Policy loaded from %s (TLS inspection enabled)\n", *policyPath)
		} else {
			// Only MITM connections to blocked domains (to render block page).
			// Allowed domains pass through via directTransfer (no TLS overhead).
			p.SetShouldInterceptRule(func(req *http.Request) bool {
				return policyAddon.ShouldIntercept(req.Host)
			})
			fmt.Printf("Policy loaded from %s (domain-level only, selective TLS for block pages)\n", *policyPath)
		}
	}

	// Start control server
	shutdown := make(chan struct{})
	controlMux := http.NewServeMux()
	controlMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	controlMux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "shutting down")
		close(shutdown)
	})
	controlMux.HandleFunc("/", handleDashboard())

	// Session APIs
	controlMux.HandleFunc("/api/sessions", sessions.HandleSessions())
	controlMux.HandleFunc("/api/domains", sessions.HandleDomains())
	controlMux.HandleFunc("/api/sessions/clear", sessions.HandleClear())

	// Event APIs
	controlMux.HandleFunc("/api/events", eventStore.HandleEvents())
	controlMux.HandleFunc("/api/events/stats", eventStore.HandleEventStats())
	controlMux.HandleFunc("/api/events/categories", eventStore.HandleCategoryStats())

	// CA cert download
	controlMux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		rootCA := p.GetCertificate()
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=\"gateweb-ca.pem\"")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Raw})
	})
	controlMux.HandleFunc("/ca.cer", func(w http.ResponseWriter, r *http.Request) {
		rootCA := p.GetCertificate()
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=\"gateweb-ca.cer\"")
		w.Write(rootCA.Raw)
	})

	// Category APIs
	controlMux.HandleFunc("/categories/lookup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			json.NewEncoder(w).Encode(map[string]string{"error": "missing ?domain= parameter"})
			return
		}
		if catSource == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"domain": domain, "categories": []string{}, "source": "none"})
			return
		}
		cat := catSource.Categorizer()
		cats := cat.Lookup(domain, "")
		json.NewEncoder(w).Encode(map[string]interface{}{"domain": domain, "categories": cats, "entries": cat.Entries()})
	})
	controlMux.HandleFunc("/categories/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if catSource == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"loaded": false, "entries": 0})
			return
		}
		cat := catSource.Categorizer()
		json.NewEncoder(w).Encode(map[string]interface{}{"loaded": true, "entries": cat.Entries()})
	})

	controlAddr := "127.0.0.1:" + *controlPort
	controlServer := &http.Server{Addr: controlAddr, Handler: controlMux}
	go func() {
		fmt.Printf("Control server on %s\n", controlAddr)
		if err := controlServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Control server error: %v\n", err)
		}
	}()

	// Start proxy in background
	go func() {
		fmt.Printf("Gateweb proxy listening on %s\n", *addr)
		if err := p.Start(); err != nil {
			fmt.Printf("Proxy stopped: %v\n", err)
		}
	}()

	// Wait for shutdown signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigs:
		fmt.Printf("\nReceived %s, shutting down...\n", sig)
	case <-shutdown:
		fmt.Println("Shutdown requested via control API...")
	}

	controlServer.Shutdown(context.Background())
	p.Shutdown(context.Background())
}

func defaultUrldbPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "categories.json"
	}
	return filepath.Join(home, ".gateweb", "categories", "urldb.json")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func downloadUrldb(destPath string) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	cf, err := ut1.Import(ut1.Options{})
	if err != nil {
		return err
	}

	data, err := json.Marshal(cf)
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	fmt.Printf("Imported %d domains from UT1\n", len(cf.Domains))
	return nil
}
