//go:build enterprise

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/sentari-dev/sentari-agent/installgate"
	hostruntime "github.com/sentari-dev/sentari-agent/runtime"
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
	debugFlag := flag.Bool("debug", false,
		"Print scan-result field counts (packages, dep edges, lockfiles, supply-chain signals, license evidence) to stderr after the scan")

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
		// Same persistence story for the install-gate signing pubkey.
		// Empty fields → SaveInstallGateTrust no-ops, which is the
		// expected case on older servers that have not yet provisioned
		// the install-gate signing key.
		if err := comms.SaveInstallGateTrust(
			certDir,
			regResp.InstallGateKeyID,
			regResp.InstallGatePubKey,
		); err != nil {
			regLog.Warn("persist install-gate trust failed", slog.String("err", err.Error()))
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

	// Same shape for the install-gate signing pubkey.  Trust file
	// missing → install-gate-disabled mode (writers will bail out
	// when verifying envelopes); base64 / length errors get logged
	// loudly so an operator noticing a corrupt trust file can
	// reset by re-registering.
	if trust, err := comms.LoadInstallGateTrust(certDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load install-gate trust: %v\n", err)
	} else if trust != nil {
		if raw, err := base64.StdEncoding.DecodeString(trust.PubKeyB64); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: install-gate pubkey is not valid base64: %v\n", err)
		} else if len(raw) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "Warning: install-gate pubkey has wrong length (%d)\n", len(raw))
		} else {
			scanner.RegisterTrustedInstallGateKey(trust.KeyID, ed25519.PublicKey(raw))
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

	// Install-gate (preventive enforcement) — Phase B.  Off by
	// default; only fetches the policy-map when the operator has
	// explicitly enabled the feature.  Off-day cost is one config
	// flag check per scan cycle.
	//
	// On-day: load cached envelope to derive the current version,
	// fetch a fresher one from the server, persist + apply.  A
	// fetch failure keeps the cached config in place rather than
	// reverting — the agent re-tries on the next cycle, and if
	// the server is durably unreachable the fail-open vs fail-
	// closed decision is the operator's via the policy-map's
	// ``fail_mode`` field (Phase D).
	if agentCfg.InstallGate.Enabled {
		igCachePath := filepath.Join(dataDir, "policy_map.json")
		currentVersion := 0
		// A cache-read error is a real signal — typically a tampered
		// or otherwise corrupt cache file.  Log and treat as
		// "no cached version" so the next FetchInstallGateMap call
		// pulls a fresh envelope.  Don't auto-delete the file: an
		// operator who needs to reproduce the corruption for a
		// support ticket would lose the evidence.
		cachedMap, _, cacheErr := scanner.LoadVerifiedInstallGateFromFile(igCachePath)
		if cacheErr != nil {
			log.Warn("install-gate cache load failed; refetching",
				slog.String("err", cacheErr.Error()))
		} else if cachedMap != nil {
			currentVersion = cachedMap.Version
		}
		// When the server-disabled marker is present, force a full
		// fetch (currentVersion=0).  Otherwise FetchInstallGateMap's
		// "version <= currentVersion → return (nil, nil, nil)" path
		// would mask a server re-enable that publishes the same
		// version we already have cached, leaving the marker stuck
		// and configs un-applied indefinitely.
		if installgate.HasServerDisabledMarker(dataDir) {
			currentVersion = 0
		}
		igMap, envelope, err := client.FetchInstallGateMap(ctx, currentVersion)
		switch {
		case errors.Is(err, comms.ErrInstallGateServerDisabled):
			// Server has explicitly disabled install-gate for this
			// tenant (404 + X-Sentari-Install-Gate-Disabled: true).
			// Tear down host configs immediately + persist a marker
			// so an agent restart between this and the next 200
			// doesn't re-write configs from the local cache.
			res, errs := installgate.RemoveAll(installGateApplyOptions(agentCfg, installgate.MarkerFields{}))
			for _, e := range errs {
				log.Warn("install-gate teardown (server disabled)", slog.String("err", e.Error()))
			}
			if mErr := installgate.WriteServerDisabledMarker(dataDir); mErr != nil {
				log.Warn("write server-disabled marker", slog.String("err", mErr.Error()))
			}
			log.Info("install-gate disabled by server (X-Sentari-Install-Gate-Disabled: true); removed host configs",
				slog.Bool("any_changed", res.AnyChanged()))
			logAudit(auditLog, "install_gate.disabled_by_server",
				fmt.Sprintf("any_changed=%t", res.AnyChanged()))
		case err != nil:
			log.Warn("install-gate refresh failed (using cached)", slog.String("err", err.Error()))
		case igMap != nil:
			// 200 with a fresher envelope.  If a previous cycle had
			// stamped the server-disabled marker, the server has
			// re-enabled — clear the marker + log + proceed with the
			// normal apply path.
			if installgate.HasServerDisabledMarker(dataDir) {
				if cErr := installgate.ClearServerDisabledMarker(dataDir); cErr != nil {
					log.Warn("clear server-disabled marker", slog.String("err", cErr.Error()))
				}
				log.Info("install-gate re-enabled by server; resuming policy enforcement")
				logAudit(auditLog, "install_gate.reenabled_by_server", "")
			}
			if err := scanner.SaveVerifiedInstallGateEnvelopeToFile(igCachePath, envelope); err != nil {
				log.Warn("failed to cache install-gate map", slog.String("err", err.Error()))
			}
			res, errs := installgate.Apply(igMap, installGateApplyOptions(agentCfg, installgate.MarkerFields{
				Version: igMap.Version,
				KeyID:   envelopeKeyID(envelope),
				Applied: time.Now().UTC(),
			}))
			for _, e := range errs {
				log.Warn("install-gate writer", slog.String("err", e.Error()))
			}
			// Surface the SkippedOperator state at info-level even
			// when nothing else changed — operators of hosts whose
			// package configs predate enrolment need to see that
			// install-gate isn't being applied there so they don't
			// conclude the feature is broken.  Maven and NuGet are
			// the two ecosystems where this matters today
			// (settings.xml and NuGet.Config commonly carry
			// operator-curated credentials).
			if res.Maven.SkippedOperator {
				log.Info("install-gate maven skipped (operator-curated settings.xml)",
					slog.String("path", res.Maven.Path),
				)
				logAudit(auditLog, "install_gate.maven.skipped_operator",
					fmt.Sprintf("path=%s version=%d", res.Maven.Path, igMap.Version))
			}
			if res.NuGet.SkippedOperator {
				log.Info("install-gate nuget skipped (operator-curated NuGet.Config)",
					slog.String("path", res.NuGet.Path),
				)
				logAudit(auditLog, "install_gate.nuget.skipped_operator",
					fmt.Sprintf("path=%s version=%d", res.NuGet.Path, igMap.Version))
			}
			if res.Uv.SkippedOperator {
				log.Info("install-gate uv skipped (operator-curated uv.toml)",
					slog.String("path", res.Uv.Path),
				)
				logAudit(auditLog, "install_gate.uv.skipped_operator",
					fmt.Sprintf("path=%s version=%d", res.Uv.Path, igMap.Version))
			}
			if res.Pdm.SkippedOperator {
				log.Info("install-gate pdm skipped (operator-curated pdm config.toml)",
					slog.String("path", res.Pdm.Path),
				)
				logAudit(auditLog, "install_gate.pdm.skipped_operator",
					fmt.Sprintf("path=%s version=%d", res.Pdm.Path, igMap.Version))
			}
			if res.Sbt.SkippedOperator {
				log.Info("install-gate sbt skipped (operator-curated repositories)",
					slog.String("path", res.Sbt.Path),
				)
				logAudit(auditLog, "install_gate.sbt.skipped_operator",
					fmt.Sprintf("path=%s version=%d", res.Sbt.Path, igMap.Version))
			}
			if res.YarnBerry.SkippedOperator {
				log.Info("install-gate yarn-berry skipped (operator-curated .yarnrc.yml)",
					slog.String("path", res.YarnBerry.Path),
				)
				logAudit(auditLog, "install_gate.yarnberry.skipped_operator",
					fmt.Sprintf("path=%s version=%d", res.YarnBerry.Path, igMap.Version))
			}
			if res.AnyChanged() {
				log.Info("install-gate applied",
					slog.Int("version", igMap.Version),
					slog.String("pip_path", res.Pip.Path),
					slog.Bool("pip_changed", res.Pip.Changed),
					slog.Bool("pip_removed", res.Pip.Removed),
					slog.String("npm_path", res.Npm.Path),
					slog.Bool("npm_changed", res.Npm.Changed),
					slog.Bool("npm_removed", res.Npm.Removed),
					slog.String("maven_path", res.Maven.Path),
					slog.Bool("maven_changed", res.Maven.Changed),
					slog.Bool("maven_removed", res.Maven.Removed),
					slog.String("nuget_path", res.NuGet.Path),
					slog.Bool("nuget_changed", res.NuGet.Changed),
					slog.Bool("nuget_removed", res.NuGet.Removed),
					slog.String("uv_path", res.Uv.Path),
					slog.Bool("uv_changed", res.Uv.Changed),
					slog.Bool("uv_removed", res.Uv.Removed),
					slog.String("pdm_path", res.Pdm.Path),
					slog.Bool("pdm_changed", res.Pdm.Changed),
					slog.Bool("pdm_removed", res.Pdm.Removed),
					slog.String("gradle_path", res.Gradle.Path),
					slog.Bool("gradle_changed", res.Gradle.Changed),
					slog.Bool("gradle_removed", res.Gradle.Removed),
					slog.String("sbt_path", res.Sbt.Path),
					slog.Bool("sbt_changed", res.Sbt.Changed),
					slog.Bool("sbt_removed", res.Sbt.Removed),
					slog.String("yarnberry_path", res.YarnBerry.Path),
					slog.Bool("yarnberry_changed", res.YarnBerry.Changed),
					slog.Bool("yarnberry_removed", res.YarnBerry.Removed),
				)
				logAudit(auditLog, "install_gate.applied",
					fmt.Sprintf("version=%d pip_path=%s pip_changed=%t pip_removed=%t "+
						"npm_path=%s npm_changed=%t npm_removed=%t "+
						"maven_path=%s maven_changed=%t maven_removed=%t "+
						"nuget_path=%s nuget_changed=%t nuget_removed=%t "+
						"uv_path=%s uv_changed=%t uv_removed=%t "+
						"pdm_path=%s pdm_changed=%t pdm_removed=%t "+
						"gradle_path=%s gradle_changed=%t gradle_removed=%t "+
						"sbt_path=%s sbt_changed=%t sbt_removed=%t "+
						"yarnberry_path=%s yarnberry_changed=%t yarnberry_removed=%t",
						igMap.Version,
						res.Pip.Path, res.Pip.Changed, res.Pip.Removed,
						res.Npm.Path, res.Npm.Changed, res.Npm.Removed,
						res.Maven.Path, res.Maven.Changed, res.Maven.Removed,
						res.NuGet.Path, res.NuGet.Changed, res.NuGet.Removed,
						res.Uv.Path, res.Uv.Changed, res.Uv.Removed,
						res.Pdm.Path, res.Pdm.Changed, res.Pdm.Removed,
						res.Gradle.Path, res.Gradle.Changed, res.Gradle.Removed,
						res.Sbt.Path, res.Sbt.Changed, res.Sbt.Removed,
						res.YarnBerry.Path, res.YarnBerry.Changed, res.YarnBerry.Removed))
			}
		}
	} else {
		// Per-host opt-out: agent.conf [install_gate] enabled = false.
		// If we previously ran with enabled=true, host config files
		// may still be in place — tear them down on first cycle so
		// the disable transition takes effect immediately rather
		// than waiting for the host to be re-imaged.  No-op when
		// nothing was Sentari-managed (operator-curated configs are
		// preserved by the per-writer isSentariManaged guard).
		res, errs := installgate.RemoveAll(installGateApplyOptions(agentCfg, installgate.MarkerFields{}))
		for _, e := range errs {
			log.Warn("install-gate teardown (per-host disable)", slog.String("err", e.Error()))
		}
		if res.AnyChanged() {
			log.Info("install-gate disabled by agent.conf; removed pre-existing host configs",
				slog.Bool("pip_removed", res.Pip.Removed),
				slog.Bool("npm_removed", res.Npm.Removed),
				slog.Bool("maven_removed", res.Maven.Removed),
				slog.Bool("nuget_removed", res.NuGet.Removed),
				slog.Bool("uv_removed", res.Uv.Removed),
				slog.Bool("pdm_removed", res.Pdm.Removed),
				slog.Bool("gradle_removed", res.Gradle.Removed),
				slog.Bool("sbt_removed", res.Sbt.Removed),
				slog.Bool("yarnberry_removed", res.YarnBerry.Removed),
			)
			logAudit(auditLog, "install_gate.disabled_by_config",
				fmt.Sprintf("pip_removed=%t npm_removed=%t maven_removed=%t nuget_removed=%t "+
					"uv_removed=%t pdm_removed=%t gradle_removed=%t sbt_removed=%t yarnberry_removed=%t",
					res.Pip.Removed, res.Npm.Removed, res.Maven.Removed, res.NuGet.Removed,
					res.Uv.Removed, res.Pdm.Removed, res.Gradle.Removed, res.Sbt.Removed, res.YarnBerry.Removed))
		}
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

	// Operator-supplied tags from agent.conf [agent] tags = ...
	// + auto-detected runtime.  Both shipped on every /scan;
	// server-side machinery in sentari PR #77 (tags) + #79 (runtime).
	// Set here rather than inside scanner.Run so the scanner package
	// stays free of agent-config + runtime-detect awareness.
	result.Tags = agentCfg.Agent.Tags
	result.Runtime = hostruntime.Detect()

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

// pipScopeFromConfig translates the operator's [install_gate]
// python_scope INI value into the writer's typed scope.  Empty
// or unrecognised → ``user`` (laptop default), matching the
// design-doc §4.1 default for non-server hosts.
func pipScopeFromConfig(s string) installgate.PipScope {
	switch s {
	case "system":
		return installgate.PipScopeSystem
	default:
		return installgate.PipScopeUser
	}
}

// npmScopeFromConfig is the npm-side parallel of pipScopeFromConfig.
// Same defaulting story — empty / unrecognised → user.
func npmScopeFromConfig(s string) installgate.NpmScope {
	switch s {
	case "system":
		return installgate.NpmScopeSystem
	default:
		return installgate.NpmScopeUser
	}
}

// mavenScopeFromConfig is the Maven-side parallel of
// pipScopeFromConfig.  System scope is a soft no-op when MAVEN_HOME
// is unset — that decision lives downstream in MavenPath.
func mavenScopeFromConfig(s string) installgate.MavenScope {
	switch s {
	case "system":
		return installgate.MavenScopeSystem
	default:
		return installgate.MavenScopeUser
	}
}

// nugetScopeFromConfig is the NuGet-side parallel.  System scope
// is a soft no-op on POSIX (no system-wide NuGet config dir);
// that decision lives downstream in NuGetPath.
func nugetScopeFromConfig(s string) installgate.NuGetScope {
	switch s {
	case "system":
		return installgate.NuGetScopeSystem
	default:
		return installgate.NuGetScopeUser
	}
}

// uvScopeFromConfig — Astral's uv has user + system config paths.
// Same defaulting story as the others: empty / unrecognised → user.
func uvScopeFromConfig(s string) installgate.UvScope {
	switch s {
	case "system":
		return installgate.UvScopeSystem
	default:
		return installgate.UvScopeUser
	}
}

// pdmScopeFromConfig — pdm has no system-wide config path; the
// system enum value soft-no-ops downstream in PdmPath.  Kept for
// symmetry with the other scope helpers.
func pdmScopeFromConfig(s string) installgate.PdmScope {
	switch s {
	case "system":
		return installgate.PdmScopeSystem
	default:
		return installgate.PdmScopeUser
	}
}

// gradleScopeFromConfig — System soft-no-ops downstream in
// GradlePath when GRADLE_HOME is unset.
func gradleScopeFromConfig(s string) installgate.GradleScope {
	switch s {
	case "system":
		return installgate.GradleScopeSystem
	default:
		return installgate.GradleScopeUser
	}
}

// sbtScopeFromConfig — System soft-no-ops downstream in SbtPath
// when SBT_HOME is unset.
func sbtScopeFromConfig(s string) installgate.SbtScope {
	switch s {
	case "system":
		return installgate.SbtScopeSystem
	default:
		return installgate.SbtScopeUser
	}
}

// yarnBerryScopeFromConfig — Yarn Berry has no system-wide config
// path; system enum value soft-no-ops downstream.
func yarnBerryScopeFromConfig(s string) installgate.YarnBerryScope {
	switch s {
	case "system":
		return installgate.YarnBerryScopeSystem
	default:
		return installgate.YarnBerryScopeUser
	}
}

// envelopeKeyID extracts the ``key_id`` field from a verified
// signed envelope's outer wrapper.  The signature itself was
// validated upstream in scanner.VerifyInstallGateEnvelope, so
// this is a safe re-decode for marker bookkeeping — we are not
// re-trusting the bytes, just lifting the already-verified key_id
// for embedding in the rendered config's ``signed=`` marker.
//
// Falls back to ``"primary"`` only when the envelope is malformed
// (which can't happen given the upstream verify) so the audit
// trail stays internally consistent rather than blank.
func envelopeKeyID(envelope []byte) string {
	var meta struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(envelope, &meta); err == nil && meta.KeyID != "" {
		return meta.KeyID
	}
	return "primary"
}

// installGateApplyOptions packages the per-ecosystem scope decisions
// from agent.conf into a single ApplyOptions struct.  Used both when
// applying a verified policy map (caller fills in marker) and when
// removing all configs on disable transitions (RemoveAll uses an
// empty marker — writers don't reference Marker on the no-endpoint
// removal branch).
func installGateApplyOptions(cfg config.AgentConfig, marker installgate.MarkerFields) installgate.ApplyOptions {
	return installgate.ApplyOptions{
		Marker:         marker,
		PipScope:       pipScopeFromConfig(cfg.InstallGate.PythonScope),
		NpmScope:       npmScopeFromConfig(cfg.InstallGate.NodeScope),
		MavenScope:     mavenScopeFromConfig(cfg.InstallGate.MavenScope),
		NuGetScope:     nugetScopeFromConfig(cfg.InstallGate.NuGetScope),
		UvScope:        uvScopeFromConfig(cfg.InstallGate.UvScope),
		PdmScope:       pdmScopeFromConfig(cfg.InstallGate.PdmScope),
		GradleScope:    gradleScopeFromConfig(cfg.InstallGate.GradleScope),
		SbtScope:       sbtScopeFromConfig(cfg.InstallGate.SbtScope),
		YarnBerryScope: yarnBerryScopeFromConfig(cfg.InstallGate.YarnBerryScope),
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
