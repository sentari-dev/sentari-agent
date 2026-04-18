//go:build enterprise

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/sbom"
	"github.com/sentari-dev/sentari-agent/scanner"
)

const (
	defaultDataDir     = "/var/lib/sentari"
	defaultAuditDBPath = "/var/lib/sentari/audit.db"
	defaultCacheDBPath = "/var/lib/sentari/cache.db"
	defaultCertDir     = "/var/lib/sentari/certs"
)

func main() {
	uploadFlag := flag.Bool("upload", false, "One-shot: register, scan, and upload to server then exit")
	serveFlag := flag.Bool("serve", false, "Daemon: continuously register, scan, and upload on a schedule")
	serverURLFlag := flag.String("server-url", "", "Override server URL from config (e.g. https://sentari.example.com)")
	configFlag := flag.String("config", "", "Path to agent config file")
	enrollTokenFlag := flag.String("enroll-token", "", "Enrollment token for first-time registration")
	enrollTokenFileFlag := flag.String("enroll-token-file", "", "Path to file containing enrollment token (avoids /proc/cmdline exposure)")
	sbomOutFlag := flag.String("sbom-out", "", "Write CycloneDX SBOM to this file path after each scan (optional)")
	dataDirFlag := flag.String("data-dir", "", "Override data directory (default: /var/lib/sentari)")
	bootstrapCAFP := flag.String("bootstrap-ca-fingerprint", "", "SHA-256 fingerprint of server TLS certificate for bootstrap pinning (hex, colon-separated)")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("sentari-agent %s (enterprise)\n", scanner.Version)
		os.Exit(0)
	}

	if !*uploadFlag && !*serveFlag {
		flag.Usage()
		os.Exit(1)
	}

	agentCfg := config.DefaultConfig()
	if *configFlag != "" {
		var err error
		agentCfg, err = config.LoadFromFile(*configFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config %s: %v\n", *configFlag, err)
			os.Exit(1)
		}
	}

	serverURL := agentCfg.Server.URL
	if *serverURLFlag != "" {
		serverURL = *serverURLFlag
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "No server URL configured. Use --server-url or set [server] url in config file.")
		os.Exit(1)
	}

	// Resolve enrollment token: --enroll-token-file takes precedence over
	// --enroll-token to avoid exposing the token in /proc/cmdline on multi-user
	// systems.
	enrollToken := *enrollTokenFlag
	if *enrollTokenFileFlag != "" {
		data, err := os.ReadFile(*enrollTokenFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read enrollment token file %s: %v\n", *enrollTokenFileFlag, err)
			os.Exit(1)
		}
		enrollToken = strings.TrimSpace(string(data))
	}
	sbomOutPath := *sbomOutFlag

	// Determine data directory (flag > default).
	dataDir := defaultDataDir
	if *dataDirFlag != "" {
		dataDir = *dataDirFlag
	}
	auditDBPath := dataDir + "/audit.db"
	cacheDBPath := dataDir + "/cache.db"

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create %s: %v\n", dataDir, err)
	}

	auditLog, err := audit.NewAuditLog(auditDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open audit log: %v\n", err)
		os.Exit(1)
	}
	defer auditLog.Close()

	scanCache, err := cache.NewCache(cacheDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open cache: %v\n", err)
		os.Exit(1)
	}
	defer scanCache.Close()

	hostname, _ := os.Hostname()

	// Determine cert paths (prefer config, fall back to data-dir/certs).
	certDir := dataDir + "/certs"
	certFile := agentCfg.Server.CertFile
	keyFile := agentCfg.Server.KeyFile
	caFile := agentCfg.Server.CACertFile
	if certFile == "" {
		certFile = certDir + "/device.crt"
	}
	if keyFile == "" {
		keyFile = certDir + "/device.key"
	}
	if caFile == "" {
		caFile = certDir + "/ca.crt"
	}

	// Map proxy config from agent config to comms proxy config.
	proxyConfig := comms.ProxyConfig{
		HTTPSProxy:   agentCfg.Proxy.HTTPSProxy,
		NoProxy:      agentCfg.Proxy.NoProxy,
		AuthUser:     agentCfg.Proxy.AuthUser,
		AuthPassFile: agentCfg.Proxy.AuthPassFile,
	}

	// Build initial (no-cert) client for registration.
	// If --bootstrap-ca-fingerprint is set, the TLS handshake will verify the
	// server's certificate fingerprint to prevent MITM during first contact.
	bootstrapClient, err := comms.NewClient(comms.ClientConfig{
		ServerURL:            serverURL,
		Timeout:              30 * time.Second,
		Proxy:                proxyConfig,
		BootstrapFingerprint: *bootstrapCAFP,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create bootstrap client: %v\n", err)
		os.Exit(1)
	}

	// Register and obtain certificates if not already present.
	if !comms.CertsExist(certDir) {
		fmt.Fprintf(os.Stderr, "Registering agent and obtaining certificates...\n")
		regResp, deviceKeyPEM, err := bootstrapClient.RegisterWithToken(hostname, enrollToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
			os.Exit(1)
		}
		if err := comms.SaveCertificates(
			certDir,
			[]byte(regResp.CACert),
			[]byte(regResp.DeviceCert),
			deviceKeyPEM,
		); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save certificates: %v\n", err)
			os.Exit(1)
		}
		if err := comms.SaveDeviceID(certDir, regResp.DeviceID); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to persist device_id: %v\n", err)
		}
		logAudit(auditLog,"agent.registered", fmt.Sprintf("device_id=%s", regResp.DeviceID))
		fmt.Fprintf(os.Stderr, "Certificates saved to %s\n", certDir)
	}

	// Build mTLS client using the saved certificates.
	client, err := comms.NewClient(comms.ClientConfig{
		ServerURL:  serverURL,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CACertFile: caFile,
		Timeout:    30 * time.Second,
		Proxy:      proxyConfig,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create mTLS client: %v\n", err)
		os.Exit(1)
	}

	// Load cached license map from disk (if available).
	licenseCachePath := filepath.Join(dataDir, "license_map.json")
	if scanner.LoadOverlayFromFile(licenseCachePath) {
		fmt.Fprintf(os.Stderr, "Loaded cached license map (version %d)\n", scanner.MapVersion())
	}

	if *uploadFlag {
		if err := runUpload(client, auditLog, scanCache, agentCfg, hostname, sbomOutPath, certDir, dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "Upload failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// --serve: daemon loop
	runServe(client, auditLog, scanCache, agentCfg, hostname, sbomOutPath, certDir, dataDir)
}

// runUpload performs a single drain-cache → scan → upload cycle.
// Registration is handled once at startup (see main()).
func runUpload(client *comms.Client, auditLog *audit.AuditLog, scanCache *cache.Cache, agentCfg config.AgentConfig, hostname, sbomOutPath, certDir, dataDir string) error {
	cycleStart := time.Now()

	// Refresh license map from server before scanning.
	if lm, err := client.FetchLicenseMap(scanner.MapVersion()); err != nil {
		fmt.Fprintf(os.Stderr, "License-map refresh failed (using cached): %v\n", err)
	} else if lm != nil {
		scanner.ApplyOverlay(*lm)
		cachePath := filepath.Join(dataDir, "license_map.json")
		if err := scanner.SaveOverlayToFile(cachePath, *lm); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to cache license map: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "License map updated to version %d\n", lm.Version)
	}

	// Drain cached scans from previous offline runs (oldest first).
	pending, err := scanCache.DequeuePending()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to read cache: %v\n", err)
	}
	drained := 0
	for _, cached := range pending {
		if uploadErr := client.UploadScan(cached.Result); uploadErr != nil {
			logAudit(auditLog, "cache.drain.failed", fmt.Sprintf("queued=%d remaining=%d err=%v", cached.QueueID, len(pending)-drained, uploadErr))
			fmt.Fprintf(os.Stderr, "Warning: failed to upload cached scan: %v\n", uploadErr)
			break // Stop draining on first failure; keep items in queue.
		}
		if markErr := scanCache.MarkUploaded(cached.QueueID); markErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to mark scan %d as uploaded: %v\n", cached.QueueID, markErr)
		}
		drained++
	}
	if drained > 0 {
		logAudit(auditLog, "cache.drain.success", fmt.Sprintf("uploaded=%d", drained))
		// Purge successfully uploaded entries older than 7 days to prevent
		// unbounded disk growth. Keeping them for a week allows forensic
		// inspection if needed.
		if purged, purgeErr := scanCache.PurgeUploaded(7 * 24 * time.Hour); purgeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cache purge failed: %v\n", purgeErr)
		} else if purged > 0 {
			fmt.Fprintf(os.Stderr, "Purged %d old cache entries\n", purged)
		}
	}

	logAudit(auditLog,"scan.started", fmt.Sprintf("hostname=%s", hostname))

	cfg := scanner.Config{
		ScanRoot:   agentCfg.Scanner.ScanRoot,
		MaxDepth:   agentCfg.Scanner.MaxDepth,
		MaxWorkers: 8,
	}

	result, err := scanner.NewScanner(cfg).Run(context.Background())
	if err != nil {
		logAudit(auditLog,"scan.failed", err.Error())
		return fmt.Errorf("scan: %w", err)
	}

	logAudit(auditLog,"scan.completed", fmt.Sprintf("packages=%d", len(result.Packages)))

	// Override scanner's local machine-id with the server-assigned UUID so the
	// server can match the scan to the registered device record.
	if serverDeviceID := comms.LoadDeviceID(certDir); serverDeviceID != "" {
		result.DeviceID = serverDeviceID
	}

	// Write local SBOM file if requested (useful for air-gapped deployments).
	if sbomOutPath != "" {
		if sbomErr := sbom.WriteCycloneDXToFile(result, sbomOutPath); sbomErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write SBOM to %s: %v\n", sbomOutPath, sbomErr)
		} else {
			fmt.Fprintf(os.Stderr, "SBOM written to %s\n", sbomOutPath)
		}
	}

	if uploadErr := client.UploadScan(result); uploadErr != nil {
		// Cache locally for the next run.
		if cacheErr := scanCache.EnqueueScan(result); cacheErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to cache scan in SQLite: %v\n", cacheErr)
			// Last resort: write scan to a JSON file so the data is not lost.
			// The file can be manually imported or inspected by operators.
			fallbackPath := filepath.Join(filepath.Dir(certDir), fmt.Sprintf("scan-fallback-%d.json", time.Now().Unix()))
			if fbData, fbErr := json.Marshal(result); fbErr == nil {
				if writeErr := os.WriteFile(fallbackPath, fbData, 0600); writeErr == nil {
					fmt.Fprintf(os.Stderr, "Scan saved to fallback file: %s\n", fallbackPath)
					logAudit(auditLog, "cache.fallback", fmt.Sprintf("path=%s", fallbackPath))
				} else {
					fmt.Fprintf(os.Stderr, "CRITICAL: scan data lost — cache and fallback file write both failed: %v\n", writeErr)
				}
			}
		}
		logAudit(auditLog, "upload.failed", uploadErr.Error())
		return fmt.Errorf("upload: %w", uploadErr)
	}

	logAudit(auditLog,"upload.success", fmt.Sprintf("packages=%d", len(result.Packages)))

	// Housekeeping: purge old uploaded entries even when no drain happened this
	// cycle.  This covers the case where a previous cycle drained but the purge
	// window hadn't elapsed yet.
	if purged, purgeErr := scanCache.PurgeUploaded(7 * 24 * time.Hour); purgeErr == nil && purged > 0 {
		fmt.Fprintf(os.Stderr, "Purged %d old cache entries\n", purged)
	}

	// Success summary — emitted on stderr so operators tailing the log see
	// heartbeat activity on every successful cycle. Without this line the
	// daemon is silent on success and looks hung to administrators.
	fmt.Fprintf(os.Stderr, "%s cycle ok: %d packages scanned and uploaded in %s\n",
		time.Now().Format(time.RFC3339),
		len(result.Packages),
		time.Since(cycleStart).Round(time.Second),
	)

	return nil
}

// runServe runs the agent as a daemon, uploading scans on a configurable schedule.
// Listens for SIGINT/SIGTERM for graceful shutdown: finishes the current cycle
// before exiting.
//
// On each cycle the agent polls the server for configuration updates. If the
// server returns a different scan_interval, the agent applies it immediately
// for the next sleep. This lets administrators change the scan frequency via the
// system_config table without restarting agents.
func runServe(client *comms.Client, auditLog *audit.AuditLog, scanCache *cache.Cache, agentCfg config.AgentConfig, hostname, sbomOutPath, certDir, dataDir string) {
	scanInterval := time.Duration(agentCfg.Scanner.Interval) * time.Second
	if scanInterval <= 0 {
		scanInterval = 3600 * time.Second
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		if err := runUpload(client, auditLog, scanCache, agentCfg, hostname, sbomOutPath, certDir, dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "Cycle error: %v\n", err)
		}

		// Poll server for configuration updates (scan interval, scan root, etc.).
		if serverCfg, err := client.PollConfig(); err == nil {
			if serverCfg.ScanInterval > 0 {
				newInterval := time.Duration(serverCfg.ScanInterval) * time.Second
				if newInterval != scanInterval {
					fmt.Fprintf(os.Stderr, "Scan interval changed: %v → %v\n", scanInterval, newInterval)
					logAudit(auditLog,"config.updated", fmt.Sprintf("scan_interval=%d", serverCfg.ScanInterval))
					scanInterval = newInterval
				}
			}
			if serverCfg.ScanRoot != "" {
				cleaned := filepath.Clean(serverCfg.ScanRoot)
				if !filepath.IsAbs(cleaned) {
					fmt.Fprintf(os.Stderr, "Ignoring non-absolute scan_root from server: %s\n", serverCfg.ScanRoot)
				} else if isScanRootDenied(cleaned) {
					fmt.Fprintf(os.Stderr, "Ignoring restricted scan_root from server: %s\n", serverCfg.ScanRoot)
				} else {
					agentCfg.Scanner.ScanRoot = cleaned
				}
			}
			if serverCfg.MaxDepth > 0 {
				agentCfg.Scanner.MaxDepth = serverCfg.MaxDepth
			}
		} else {
			fmt.Fprintf(os.Stderr, "Config poll failed (using cached interval %v): %v\n", scanInterval, err)
		}

		// Sleep with ±10% jitter to avoid thundering-herd on the server.
		// Use crypto/rand for unpredictable timing — math/rand would make
		// scan intervals predictable to a network observer.
		jitter := cryptoJitter(scanInterval)
		sleepDuration := scanInterval + jitter
		nextCycleAt := time.Now().Add(sleepDuration)
		fmt.Fprintf(os.Stderr, "%s sleeping for %s — next cycle at %s\n",
			time.Now().Format(time.RFC3339),
			sleepDuration.Round(time.Second),
			nextCycleAt.Format(time.RFC3339),
		)
		sleepTimer := time.NewTimer(sleepDuration)

		select {
		case sig := <-sigCh:
			sleepTimer.Stop()
			fmt.Fprintf(os.Stderr, "Received %s — shutting down gracefully\n", sig)
			logAudit(auditLog,"agent.shutdown", fmt.Sprintf("signal=%s", sig))
			return
		case <-sleepTimer.C:
			// Next cycle.
		}
	}
}

// logAudit writes an audit entry and logs to stderr on failure.
// Audit logging should never be silently discarded — if the audit database
// is unavailable, the operator must be aware.
func logAudit(a *audit.AuditLog, eventType, detail string) {
	if err := a.Log(eventType, detail); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: audit log write failed (%s): %v\n", eventType, err)
	}
}

// cryptoJitter returns a random duration in [-interval/10, +interval/10] using
// crypto/rand so that scan timing is not predictable to a network observer.
func cryptoJitter(interval time.Duration) time.Duration {
	window := int64(interval / 10)
	if window <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(window*2))
	if err != nil {
		return 0 // Fallback: no jitter on entropy failure.
	}
	return time.Duration(n.Int64() - window)
}

// isScanRootDenied returns true if the given path is in the denylist of
// sensitive directories that must not be used as a scan root.  This prevents
// a compromised server from directing the agent to exfiltrate filesystem
// layout information via scan errors.
func isScanRootDenied(cleaned string) bool {
	denied := []string{"/etc", "/root", "/home", "/proc", "/sys", "/var/log", "/dev", "/run"}
	for _, prefix := range denied {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
			return true
		}
	}
	return false
}
