//go:build enterprise

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/sbom"
	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/containers"
	// Blank imports: pull in plugin packages so their init()
	// registers with scanner's registry at binary startup.  See
	// the matching comment in main.go (OSS build).
	_ "github.com/sentari-dev/sentari-agent/scanner/aiagents"
	_ "github.com/sentari-dev/sentari-agent/scanner/jvm"
	_ "github.com/sentari-dev/sentari-agent/scanner/npm"
	_ "github.com/sentari-dev/sentari-agent/scanner/nuget"
)

const (
	defaultDataDir     = "/var/lib/sentari"
	defaultAuditDBPath = "/var/lib/sentari/audit.db"
	defaultCacheDBPath = "/var/lib/sentari/cache.db"
	defaultCertDir     = "/var/lib/sentari/certs"
)

func main() {
	// Mode flags.  --scan mirrors the community build: run a
	// local scan, format, exit, no upload, no network.  Present
	// in enterprise too per the 2026-04-24 OSS ⊆ Enterprise
	// decision — an enterprise operator who wants a local
	// one-shot diagnostic can reach for it without switching
	// binaries or triggering a server round-trip.
	scanFlag := flag.Bool("scan", false, "One-shot local scan with formatted output to stdout or --output (no server round-trip)")
	uploadFlag := flag.Bool("upload", false, "One-shot: register, scan, and upload to server then exit")
	serveFlag := flag.Bool("serve", false, "Daemon: continuously register, scan, and upload on a schedule")

	// --scan companion flags (shared shape with the community build).
	outputFlag := flag.String("output", "", "Output file path for --scan (default: stdout)")
	formatFlag := flag.String("format", "",
		"Output format for --scan: pretty | explain | json | csv  (default: pretty on stdout, json to --output)")
	explainFlag := flag.Bool("explain", false,
		"Shorthand for --format=explain when used with --scan")

	serverURLFlag := flag.String("server-url", "", "Override server URL from config (e.g. https://sentari.example.com)")
	configFlag := flag.String("config", "", "Path to agent config file")
	enrollTokenFlag := flag.String("enroll-token", "", "Enrollment token for first-time registration")
	enrollTokenFileFlag := flag.String("enroll-token-file", "", "Path to file containing enrollment token (avoids /proc/cmdline exposure)")
	sbomOutFlag := flag.String("sbom-out", "", "Write CycloneDX SBOM to this file path after each scan (optional)")
	dataDirFlag := flag.String("data-dir", "", "Override data directory (default: /var/lib/sentari)")
	bootstrapCAFP := flag.String("bootstrap-ca-fingerprint", "", "SHA-256 fingerprint of server TLS certificate for bootstrap pinning (hex, colon-separated)")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	// Structured logging goes first — every line emitted after this
	// point inherits the JSON format + the request_id contextvar.
	logging.Configure()

	if *versionFlag {
		fmt.Printf("sentari-agent %s (enterprise)\n", scanner.Version)
		os.Exit(0)
	}

	// --scan runs before the --upload / --serve branches so
	// enterprise operators can invoke the community-style
	// one-shot diagnostic without any of the registration /
	// cert-bootstrap / upload machinery firing.  Mutually
	// exclusive with --upload and --serve: a host either
	// scans locally or scans-and-uploads, not both in the
	// same invocation.
	if *scanFlag {
		if *uploadFlag || *serveFlag {
			fmt.Fprintln(os.Stderr, "--scan is mutually exclusive with --upload / --serve")
			os.Exit(1)
		}
		agentCfgLocal := config.DefaultConfig()
		if *configFlag != "" {
			var err error
			agentCfgLocal, err = config.LoadFromFile(*configFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load config %s: %v\n", *configFlag, err)
				os.Exit(1)
			}
		}
		cfg := scanner.Config{
			ScanRoot:       agentCfgLocal.Scanner.ScanRoot,
			MaxDepth:       agentCfgLocal.Scanner.MaxDepth,
			MaxWorkers:     8,
			ScanContainers: agentCfgLocal.Scanner.ScanContainers,
		}
		if v := os.Getenv("SENTARI_SCAN_CONTAINERS"); v == "true" || v == "1" {
			cfg.ScanContainers = true
		}
		os.Exit(runOneShot(context.Background(), cfg, oneShotOptions{
			outputPath: *outputFlag,
			format:     *formatFlag,
			explain:    *explainFlag,
		}))
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
		// Mint the bootstrap request_id first, then bind every log
		// line in the registration block to it.  Previously the
		// "registering agent" / "save certificates failed" lines
		// used bare slog calls, so none of them carried the
		// request_id the outbound request was about to stamp onto
		// the wire — correlating an agent enrol with the server log
		// was harder than it should be.
		regCtx := logging.WithRequestID(context.Background(), logging.NewRequestID())
		regLog := logging.LoggerFromContext(regCtx)

		regLog.Info("registering agent", slog.String("hostname", hostname))
		regResp, deviceKeyPEM, err := bootstrapClient.RegisterWithToken(regCtx, hostname, enrollToken)
		if err != nil {
			regLog.Error("registration failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
		if err := comms.SaveCertificates(
			certDir,
			[]byte(regResp.CACert),
			[]byte(regResp.DeviceCert),
			deviceKeyPEM,
		); err != nil {
			regLog.Error("save certificates failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
		if err := comms.SaveDeviceID(certDir, regResp.DeviceID); err != nil {
			regLog.Warn("persist device_id failed", slog.String("err", err.Error()))
		}
		// Persist the server's license-map signing pubkey so subsequent
		// scan cycles can verify signed /license-map envelopes without
		// an operator-supplied pin.  Trust is anchored at the same TLS-
		// fingerprint bootstrap the cert issuance relies on.
		if err := comms.SaveLicenseMapTrust(
			certDir,
			regResp.LicenseMapKeyID,
			regResp.LicenseMapPubKey,
		); err != nil {
			regLog.Warn("persist license-map trust failed", slog.String("err", err.Error()))
		}
		logAudit(auditLog, "agent.registered", fmt.Sprintf("device_id=%s", regResp.DeviceID))
		regLog.Info("certificates saved", slog.String("cert_dir", certDir))
	}

	// Load the persisted license-map trust (learned at register time)
	// and register it with the scanner so envelope verification can
	// find a pubkey under the matching key_id.  A missing or invalid
	// trust file is non-fatal: the agent just won't fetch/apply
	// license-map overlays, it'll fall back to the compiled-in defaults.
	if trust, err := comms.LoadLicenseMapTrust(certDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load license-map trust: %v\n", err)
	} else if trust != nil {
		if raw, err := base64.StdEncoding.DecodeString(trust.PubKeyB64); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: license-map pubkey is not valid base64: %v\n", err)
		} else if len(raw) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "Warning: license-map pubkey has wrong length (%d)\n", len(raw))
		} else {
			scanner.RegisterTrustedMapKey(trust.KeyID, ed25519.PublicKey(raw))
		}
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

	// Load cached license map from disk (if available).  The cache
	// holds a signed envelope; LoadVerifiedOverlayFromFile re-verifies
	// the signature on every load so disk tampering cannot silently
	// reclassify licenses.  Failures fall through to the compiled-in
	// defaults; no stale/invalid overlay is ever applied.
	licenseCachePath := filepath.Join(dataDir, "license_map.json")
	if scanner.LoadVerifiedOverlayFromFile(licenseCachePath) {
		fmt.Fprintf(os.Stderr, "Loaded cached license map (version %d)\n", scanner.MapVersion())
	}

	if *uploadFlag {
		ctx := logging.WithRequestID(context.Background(), logging.NewRequestID())
		if err := runUpload(ctx, client, auditLog, scanCache, agentCfg, hostname, sbomOutPath, certDir, dataDir); err != nil {
			logging.LoggerFromContext(ctx).Error("upload cycle failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
		return
	}

	// --serve: daemon loop
	runServe(client, auditLog, scanCache, agentCfg, hostname, sbomOutPath, certDir, dataDir)
}

// runUpload performs a single drain-cache → scan → upload cycle.
// Registration is handled once at startup (see main()).
//
// ctx carries the cycle's request_id; every HTTP call and every log
// line inside this cycle is stamped with it so the server-side trace
// ("scan received", "CVE correlation fired", "alert delivered") joins
// back to this single agent cycle.
func runUpload(ctx context.Context, client *comms.Client, auditLog *audit.AuditLog, scanCache *cache.Cache, agentCfg config.AgentConfig, hostname, sbomOutPath, certDir, dataDir string) error {
	cycleStart := time.Now()
	log := logging.LoggerFromContext(ctx)

	// Refresh license map from server before scanning.  The response
	// is a signed envelope; FetchLicenseMap verifies it and returns
	// the raw envelope bytes so we can cache them for offline re-
	// verification next startup.  On any verification failure we keep
	// serving the previously-cached overlay — never apply unverified
	// data.
	if lm, envelope, err := client.FetchLicenseMap(ctx, scanner.MapVersion()); err != nil {
		log.Warn("license-map refresh failed (using cached)", slog.String("err", err.Error()))
	} else if lm != nil {
		scanner.ApplyOverlay(*lm)
		cachePath := filepath.Join(dataDir, "license_map.json")
		if err := scanner.SaveVerifiedEnvelopeToFile(cachePath, envelope); err != nil {
			log.Warn("failed to cache license map", slog.String("err", err.Error()))
		}
		log.Info("license map updated", slog.Int("version", lm.Version))
	}

	// Drain cached scans from previous offline runs (oldest first).
	pending, err := scanCache.DequeuePending()
	if err != nil {
		log.Warn("failed to read cache", slog.String("err", err.Error()))
	}
	drained := 0
	for _, cached := range pending {
		if uploadErr := client.UploadScan(ctx, cached.Result); uploadErr != nil {
			logAudit(auditLog, "cache.drain.failed", fmt.Sprintf("queued=%d remaining=%d err=%v", cached.QueueID, len(pending)-drained, uploadErr))
			log.Warn("failed to upload cached scan",
				slog.Int64("queue_id", cached.QueueID),
				slog.String("err", uploadErr.Error()),
			)
			break // Stop draining on first failure; keep items in queue.
		}
		if markErr := scanCache.MarkUploaded(cached.QueueID); markErr != nil {
			log.Warn("failed to mark scan as uploaded",
				slog.Int64("queue_id", cached.QueueID),
				slog.String("err", markErr.Error()),
			)
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
		ScanRoot:       agentCfg.Scanner.ScanRoot,
		MaxDepth:       agentCfg.Scanner.MaxDepth,
		MaxWorkers:     8,
		ScanContainers: agentCfg.Scanner.ScanContainers,
	}
	if v := os.Getenv("SENTARI_SCAN_CONTAINERS"); v == "true" || v == "1" {
		cfg.ScanContainers = true
	}

	result, err := scanner.NewScanner(cfg).Run(ctx)
	if err != nil {
		logAudit(auditLog,"scan.failed", err.Error())
		return fmt.Errorf("scan: %w", err)
	}

	// Opt-in container-scan phase.  Failures here never bubble up
	// — the host scan already succeeded and we don't want one
	// bad image to derail the upload.
	if cfg.ScanContainers {
		containers.ScanAndAppend(ctx, cfg, result)
	}

	logAudit(auditLog,"scan.completed", fmt.Sprintf("packages=%d containers=%d",
		len(result.Packages), len(result.ContainerTargets)))

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

	if uploadErr := client.UploadScan(ctx, result); uploadErr != nil {
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
		// Fresh request_id per cycle.  One scan, one CVE-correlation
		// wave, one alert-delivery fan-out — all join on this ID.
		ctx := logging.WithRequestID(context.Background(), logging.NewRequestID())
		log := logging.LoggerFromContext(ctx)

		if err := runUpload(ctx, client, auditLog, scanCache, agentCfg, hostname, sbomOutPath, certDir, dataDir); err != nil {
			log.Error("cycle error", slog.String("err", err.Error()))
		}

		// Poll server for configuration updates (scan interval, scan root, etc.).
		if serverCfg, err := client.PollConfig(ctx); err == nil {
			if serverCfg.ScanInterval > 0 {
				newInterval := time.Duration(serverCfg.ScanInterval) * time.Second
				if newInterval != scanInterval {
					log.Info("scan interval changed",
						slog.Duration("old", scanInterval),
						slog.Duration("new", newInterval),
					)
					logAudit(auditLog, "config.updated", fmt.Sprintf("scan_interval=%d", serverCfg.ScanInterval))
					scanInterval = newInterval
				}
			}
			if serverCfg.ScanRoot != "" {
				cleaned := filepath.Clean(serverCfg.ScanRoot)
				if !filepath.IsAbs(cleaned) {
					log.Warn("ignoring non-absolute scan_root from server", slog.String("scan_root", serverCfg.ScanRoot))
				} else if isScanRootDenied(cleaned) {
					log.Warn("ignoring restricted scan_root from server", slog.String("scan_root", serverCfg.ScanRoot))
				} else {
					agentCfg.Scanner.ScanRoot = cleaned
				}
			}
			if serverCfg.MaxDepth > 0 {
				agentCfg.Scanner.MaxDepth = serverCfg.MaxDepth
			}
		} else {
			log.Warn("config poll failed (using cached interval)",
				slog.Duration("interval", scanInterval),
				slog.String("err", err.Error()),
			)
		}

		// Sleep with ±10% jitter to avoid thundering-herd on the server.
		// Use crypto/rand for unpredictable timing — math/rand would make
		// scan intervals predictable to a network observer.
		jitter := cryptoJitter(scanInterval)
		sleepDuration := scanInterval + jitter
		nextCycleAt := time.Now().Add(sleepDuration)
		log.Info("sleeping until next cycle",
			slog.Duration("sleep", sleepDuration),
			slog.String("next_at", nextCycleAt.Format(time.RFC3339)),
		)
		sleepTimer := time.NewTimer(sleepDuration)

		select {
		case sig := <-sigCh:
			sleepTimer.Stop()
			log.Info("shutting down gracefully", slog.String("signal", sig.String()))
			logAudit(auditLog, "agent.shutdown", fmt.Sprintf("signal=%s", sig))
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
