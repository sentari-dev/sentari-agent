//go:build enterprise

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/common/secureperm"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	// Blank imports: pull in plugin packages so their init()
	// registers with scanner's registry at binary startup.  See
	// the matching comment in main.go (OSS build).
	_ "github.com/sentari-dev/sentari-agent/scanner/aiagents"
	_ "github.com/sentari-dev/sentari-agent/scanner/gobinaries"
	_ "github.com/sentari-dev/sentari-agent/scanner/jvm"
	_ "github.com/sentari-dev/sentari-agent/scanner/npm"
	_ "github.com/sentari-dev/sentari-agent/scanner/nuget"
)

// defaultDataDir is the agent's state directory (audit DB, scan cache,
// device certificates).  Platform-aware: %ProgramData%\Sentari on Windows,
// /var/lib/sentari on POSIX.  Operators override with --data-dir.
var defaultDataDir = platformDefaultDataDir()

// platformDefaultDataDir returns the OS-appropriate default state directory.
// On Windows the POSIX /var/lib path is meaningless (it would resolve to
// \var\lib\sentari on the current drive); %ProgramData% is the conventional
// machine-wide, service-writable location.
func platformDefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Sentari")
		}
		return `C:\ProgramData\Sentari`
	}
	return "/var/lib/sentari"
}

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
	debugFlag := flag.Bool("debug", false,
		"Print scan-result field counts (packages, dep edges, lockfiles, supply-chain signals, license evidence) to stderr after the scan")

	serverURLFlag := flag.String("server-url", "", "Override server URL from config (e.g. https://sentari.example.com)")
	configFlag := flag.String("config", "", "Path to agent config file")
	enrollTokenFlag := flag.String("enroll-token", "", "Enrollment token for first-time registration")
	enrollTokenFileFlag := flag.String("enroll-token-file", "", "Path to file containing enrollment token (avoids /proc/cmdline exposure)")
	sbomOutFlag := flag.String("sbom-out", "", "Write an SBOM to this file path after each scan (optional; format selected by --sbom-format)")
	sbomFormatFlag := flag.String("sbom-format", "cyclonedx", "SBOM format for --sbom-out: cyclonedx | spdx (default cyclonedx)")
	dataDirFlag := flag.String("data-dir", "", "Override data directory (default: /var/lib/sentari on POSIX, %ProgramData%\\Sentari on Windows)")
	bootstrapCAFP := flag.String("bootstrap-ca-fingerprint", "", "SHA-256 fingerprint of server TLS certificate for bootstrap pinning (hex, colon-separated)")
	excludeNetworkPathsFlag := flag.Bool(
		"exclude-network-paths",
		false,
		"Skip runtime detection inside network-mounted filesystems (NFS, SMB/CIFS, WebDAV, FUSE remotes). Defaults to off — every filesystem is scanned. Cloud-synced subtrees (iCloud, Dropbox, OneDrive, Google Drive on macOS) are always skipped regardless of this flag.",
	)
	updateCheckFlag := flag.Bool("update-check", false, "Probe the server for a newer agent release; print the plan and exit (no mutation, no service restart)")
	updateApplyFlag := flag.Bool("update-apply", false, "Probe, download, verify, atomically replace this binary, and restart the agent service")
	updateRollbackFlag := flag.Bool("update-rollback", false, "Restore the previous binary (kept at <install-path>.prev by --update-apply) and restart the service")
	updateInstallPathFlag := flag.String("update-install-path", "", "Override the install-path target of --update-apply / --update-rollback (default: this binary's own path via os.Executable())")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	// Wire the network-path exclusion through the package-level toggle
	// the runtime walkers consult.  Done immediately after flag.Parse
	// so any subsequent code path sees the configured value.
	pathfilter.ExcludeNetworkPaths = *excludeNetworkPathsFlag

	// Structured logging goes first — every line emitted after this
	// point inherits the JSON format + the request_id contextvar.
	logging.Configure()

	if *versionFlag {
		fmt.Printf("sentari-agent %s (enterprise)\n", scanner.Version)
		os.Exit(0)
	}

	// Update mode — mutually exclusive with --scan / --upload /
	// --serve.  Runs the self-update flow against the server's
	// signed release manifest and exits.
	updateModeSelected := 0
	if *updateCheckFlag {
		updateModeSelected++
	}
	if *updateApplyFlag {
		updateModeSelected++
	}
	if *updateRollbackFlag {
		updateModeSelected++
	}
	if updateModeSelected > 0 {
		if updateModeSelected > 1 {
			fmt.Fprintln(os.Stderr, "--update-check / --update-apply / --update-rollback are mutually exclusive")
			os.Exit(1)
		}
		if *scanFlag || *uploadFlag || *serveFlag {
			fmt.Fprintln(os.Stderr, "--update-* flags are mutually exclusive with --scan / --upload / --serve")
			os.Exit(1)
		}
		// Load agent config the same way the upload/serve paths do
		// so --config and the default-config code path both work.
		agentCfgLocal := config.DefaultConfig()
		if *configFlag != "" {
			var err error
			agentCfgLocal, err = config.LoadFromFile(*configFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load config %s: %v\n", *configFlag, err)
				os.Exit(1)
			}
		}
		dataDirLocal := defaultDataDir
		if *dataDirFlag != "" {
			dataDirLocal = *dataDirFlag
		}
		mode := updateModeCheck
		switch {
		case *updateApplyFlag:
			mode = updateModeApply
		case *updateRollbackFlag:
			mode = updateModeRollback
		}
		os.Exit(runUpdate(mode, agentCfgLocal, *serverURLFlag, dataDirLocal, *updateInstallPathFlag))
	}

	// --scan lets enterprise operators invoke the community-style
	// one-shot diagnostic without any of the registration /
	// cert-bootstrap / upload machinery firing.  Mutually exclusive
	// with --upload and --serve: a host either scans locally or
	// scans-and-uploads, not both in the same invocation.
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
			debug:      *debugFlag,
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

	// Apply the operator's offline-queue cap (or the default) before the cache
	// is opened and the first scan is enqueued.  Validated non-negative in the
	// config parser.
	cache.SetMaxPendingScans(agentCfg.Cache.MaxPendingScans)
	cache.SetMaxPendingBytes(agentCfg.Cache.MaxPendingBytes)

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
		// TrimPrefix strips a leading UTF-8 BOM (U+FEFF) that Windows
		// PowerShell's Set-Content -Encoding UTF8 can prepend; it is not
		// Unicode whitespace so TrimSpace does not remove it.
		enrollToken = strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff")
	}
	sbomOutPath := *sbomOutFlag
	// Validate the SBOM format up front (only meaningful alongside --sbom-out)
	// so an unknown value fails fast at startup rather than warning on every
	// scan cycle.  normalizeSBOMFormat rejects anything but cyclonedx | spdx.
	sbomFormat, err := normalizeSBOMFormat(*sbomFormatFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Determine data directory (flag > default).
	dataDir := defaultDataDir
	if *dataDirFlag != "" {
		dataDir = *dataDirFlag
	}
	auditDBPath := filepath.Join(dataDir, "audit.db")
	cacheDBPath := filepath.Join(dataDir, "cache.db")

	// Colocate the persisted macOS device-id file with the agent data dir so
	// it lives alongside the cache/audit DBs rather than a separate default
	// location.  No-op on platforms that derive the device id elsewhere.
	scanner.SetDeviceIDDataDir(dataDir)

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create %s: %v\n", dataDir, err)
	}
	// Lock the data dir down to the service account.  On Windows this strips
	// the default inherited "Users" read access (mode bits are ignored there)
	// so the device private key and audit DB beneath it are not world-readable;
	// the restrictive ACE is inheritable, covering the cert subdir written
	// later during registration.  On POSIX it re-asserts 0700.
	if err := secureperm.HardenDir(dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not restrict permissions on %s: %v\n", dataDir, err)
	}

	// Open the audit log resiliently: a corrupt audit DB (truncated file,
	// damaged header, not-a-database) must not brick the daemon at startup, the
	// same guarantee the scan cache already had.  OpenResilient quarantines the
	// bad file aside and starts a FRESH hash chain (its first entry is a loud
	// "audit.recreated" marker); the quarantined file preserves the old chain
	// for forensics.  A transient error (disk full, permission denied) is NOT
	// recovered from — it is returned so we exit and retry with the chain intact.
	auditLog, auditRecovered, auditCorruptPath, err := audit.OpenResilient(auditDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open audit log: %v\n", err)
		os.Exit(1)
	}
	defer auditLog.Close()
	if auditRecovered {
		fmt.Fprintf(os.Stderr,
			"WARNING: audit DB was corrupt; quarantined to %s and started a fresh hash chain "+
				"(the old chain is preserved there for forensic inspection)\n",
			auditCorruptPath)
	}

	// Bound the audit log's on-disk growth: apply the operator's retention cap
	// (or the bounded default, config.DefaultMaxAuditBytes = 256 MiB) before any
	// entry is written, so the MarkShipped retention purge reclaims the oldest
	// SHIPPED rows above the cap.  Validated non-negative in the config parser;
	// 0 disables the cap.  UNSHIPPED (not-yet-server-witnessed) rows are never
	// purged, so a long air-gap window still retains all undelivered evidence.
	audit.SetMaxAuditBytes(agentCfg.Audit.MaxAuditBytes)

	// Open the scan cache resiliently: a corrupt cache DB (truncated file,
	// damaged header, not-a-database) must not brick the daemon.  OpenResilient
	// quarantines the bad file aside and recreates an empty queue; only a
	// second failure is fatal.
	scanCache, cacheRecovered, cacheCorruptPath, err := cache.OpenResilient(cacheDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open cache: %v\n", err)
		os.Exit(1)
	}
	defer scanCache.Close()
	if cacheRecovered {
		fmt.Fprintf(os.Stderr,
			"WARNING: cache DB was corrupt; quarantined to %s and recreated an empty queue "+
				"(any un-drained offline scans in the old file are preserved there for inspection)\n",
			cacheCorruptPath)
		logAudit(auditLog, "cache.recreated",
			fmt.Sprintf("corrupt_db_quarantined=%s", cacheCorruptPath))
	}

	hostname, _ := os.Hostname()

	// Determine cert paths (prefer config, fall back to data-dir/certs).
	certDir := filepath.Join(dataDir, "certs")
	certFile := agentCfg.Server.CertFile
	keyFile := agentCfg.Server.KeyFile
	caFile := agentCfg.Server.CACertFile
	if certFile == "" {
		certFile = filepath.Join(certDir, "device.crt")
	}
	if keyFile == "" {
		keyFile = filepath.Join(certDir, "device.key")
	}
	if caFile == "" {
		caFile = filepath.Join(certDir, "ca.crt")
	}

	// The mTLS client loads its material from certFile/keyFile/caFile above.
	// The registration gate, the renewal save/read, and the post-renewal
	// client rebuild must all operate on these SAME resolved paths — not the
	// hardcoded certDir/device.crt convention — so a config-overridden cert
	// path rotates (and is existence-checked) where the client actually looks.
	certPaths := comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}

	// Map proxy config from agent config to comms proxy config.
	proxyConfig := comms.ProxyConfig{
		HTTPSProxy:   agentCfg.Proxy.HTTPSProxy,
		NoProxy:      agentCfg.Proxy.NoProxy,
		AuthUser:     agentCfg.Proxy.AuthUser,
		AuthPassFile: agentCfg.Proxy.AuthPassFile,
	}

	// Build initial (no-cert) client for registration.
	// Trust precedence per ADR 0004: an operator-distributed CA cert
	// (ca_cert_file in the config — NOT the certs-dir fallback, which does
	// not exist before registration) anchors the bootstrap handshake via
	// standard chain validation.  If --bootstrap-ca-fingerprint is also
	// set, the fingerprint pin runs as an additional check; with a
	// fingerprint alone, the pin is the sole verification.
	bootstrapClient, err := comms.NewClient(comms.ClientConfig{
		ServerURL:            serverURL,
		Timeout:              30 * time.Second,
		Proxy:                proxyConfig,
		CACertFile:           agentCfg.Server.CACertFile,
		BootstrapFingerprint: *bootstrapCAFP,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create bootstrap client: %v\n", err)
		os.Exit(1)
	}

	// Register and obtain certificates if not already present.  Checks the
	// resolved (possibly config-overridden) cert paths the client uses, so a
	// custom-path deployment with valid certs does not spuriously re-register.
	if !comms.CertsExistAt(certPaths) {
		// Mint the bootstrap request_id first, then bind every log
		// line in the registration block to it.  Previously the
		// "registering agent" / "save certificates failed" lines
		// used bare slog calls, so none of them carried the
		// request_id the outbound request was about to stamp onto
		// the wire — correlating an agent enrol with the server log
		// was harder than it should be.
		regCtx := logging.WithRequestID(context.Background(), logging.NewRequestID())
		if err := registerAndSaveCerts(regCtx, bootstrapClient, hostname, enrollToken, certPaths, certDir, auditLog); err != nil {
			logging.LoggerFromContext(regCtx).Error("registration failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}

	// Load the persisted signing-pubkey trust (learned at register time) and
	// register it with the scanner keyring so envelope verification can find a
	// pubkey under the matching key_id.  Missing/invalid trust files are
	// non-fatal — the agent falls back to compiled-in defaults.  The same
	// helper runs again after a successful cert renewal (which may carry a
	// rotated signing key) so a key rotation takes effect without a restart.
	loadSigningTrustIntoKeyring(certDir)

	// Build mTLS client using the saved certificates.
	//
	// Timeout has to cover the worst call this client makes, which is the
	// scan-upload round-trip: on a real fleet device the v3 payload carries
	// ~15-20k packages plus license/dep-graph/supply-chain evidence, and
	// the server's ingest path (UPSERT into 8+ tables + license enrichment
	// + CVE correlation) routinely takes 60-120 seconds end-to-end before
	// returning 200. A 30 s ceiling silently re-queues every cycle on those
	// devices even though the server completes the ingest. 5 minutes gives
	// the server room to finish without giving up on genuinely dead sockets.
	// Smaller endpoints on this client (config fetch, log telemetry, cert
	// renewal) all respond in well under a second, so the larger ceiling
	// doesn't slow their failure mode in any meaningful way.
	client, err := comms.NewClient(comms.ClientConfig{
		ServerURL:  serverURL,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CACertFile: caFile,
		Timeout:    5 * time.Minute,
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

	// Per-cycle operational params (host identity, SBOM target, resolved
	// dirs), grouped so the upload / serve call chain passes one value instead
	// of five consecutive strings.
	cp := cycleParams{
		hostname:    hostname,
		sbomOutPath: sbomOutPath,
		sbomFormat:  sbomFormat,
		certDir:     certDir,
		dataDir:     dataDir,
	}

	if *uploadFlag {
		ctx := logging.WithRequestID(context.Background(), logging.NewRequestID())
		// One-shot: no cross-cycle state, so pass a nil debouncer — a
		// single server-disable signal tears down, matching run-once
		// semantics.
		if err := runUpload(ctx, client, auditLog, scanCache, agentCfg, cp, nil); err != nil {
			logging.LoggerFromContext(ctx).Error("upload cycle failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
		return
	}

	// --serve: daemon loop.  Pass the mTLS-client material so the loop can
	// rebuild its client in-memory after a certificate renewal (same config as
	// the client built above).
	renewCfg := renewClientConfig{
		serverURL: serverURL,
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		timeout:   5 * time.Minute,
		proxy:     proxyConfig,
	}

	// Bootstrap material for cert-expiry re-enrollment (finding offline-7).  If
	// the device cert lapses during an outage longer than its remaining validity
	// (renewal never got a chance to run), the serve loop can re-register using
	// this token+trust rather than looping forever on TLS handshake failures.
	bp := bootstrapParams{
		serverURL:            serverURL,
		proxy:                proxyConfig,
		caCertFile:           agentCfg.Server.CACertFile,
		bootstrapFingerprint: *bootstrapCAFP,
		enrollToken:          enrollToken,
		certPaths:            certPaths,
		certDir:              certDir,
	}

	// Startup cert-expiry check: if the on-disk device cert has already expired
	// (a long air-gap window that outlasted the cert), re-enroll now — or, with
	// no token configured, log a single actionable error — before entering the
	// serve loop, instead of letting the first upload fail with opaque TLS noise.
	{
		startupCtx := logging.WithRequestID(context.Background(), logging.NewRequestID())
		client = maybeReenrollOnExpiredCert(startupCtx, client, bp, renewCfg, hostname, auditLog)
	}

	// Under the Windows Service Control Manager (SCM), the process must call
	// the service dispatcher and answer StartPending/Running/Stop callbacks —
	// otherwise `sc start` / auto-start fails with error 1053 ("service did
	// not respond in a timely fashion") and crash-loops.  runServeUnderService
	// runs serveLoop inside svc.Run, cancelling its root context on a Stop /
	// Shutdown control request — the same graceful teardown SIGTERM triggers.
	// This check happens BEFORE runServe installs the unix signal handler.
	//
	// On non-Windows hosts, and on Windows when launched from a console rather
	// than the SCM, runServeUnderService is a no-op returning ran=false and we
	// fall through to the signal-driven console path below unchanged.
	serve := func(ctx context.Context, shutdownReason func() string) {
		serveLoop(ctx, shutdownReason, client, auditLog, scanCache, agentCfg, cp, renewCfg, bp)
	}
	if ran, err := runServeUnderService(serve); err != nil {
		fmt.Fprintf(os.Stderr, "Windows service dispatcher failed: %v\n", err)
		os.Exit(1)
	} else if ran {
		return
	}

	runServe(client, auditLog, scanCache, agentCfg, cp, renewCfg, bp)
}

// logAudit writes an audit entry and logs to stderr on failure.
// Audit logging should never be silently discarded — if the audit database
// is unavailable, the operator must be aware.
func logAudit(a *audit.AuditLog, eventType, detail string) {
	if err := a.Log(eventType, detail); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: audit log write failed (%s): %v\n", eventType, err)
	}
}
