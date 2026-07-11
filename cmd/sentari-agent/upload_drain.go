//go:build enterprise

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/common/dbhealth"
	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/installgate"
	hostruntime "github.com/sentari-dev/sentari-agent/runtime"
	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/containers"
)

// runUpload performs a single drain-cache → scan → upload cycle.
// Registration is handled once at startup (see main()).
//
// ctx carries the cycle's request_id; every HTTP call and every log
// line inside this cycle is stamped with it so the server-side trace
// ("scan received", "CVE correlation fired", "alert delivered") joins
// back to this single agent cycle.
func runUpload(ctx context.Context, client *comms.Client, auditLog *audit.AuditLog, scanCache *cache.Cache, agentCfg config.AgentConfig, cp cycleParams, igDisableDebounce *comms.InstallGateDisableDebouncer) error {
	// Destructure the per-cycle params once so the cycle body below reads the
	// same local names it always has.
	hostname, sbomOutPath, sbomFormat := cp.hostname, cp.sbomOutPath, cp.sbomFormat
	certDir, dataDir := cp.certDir, cp.dataDir

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
	// `fail_mode` field (Phase D).
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
			//
			// Debounce: require N consecutive disable responses before
			// tearing down host configs, so a single transient/buggy
			// server response can't wipe every managed host config
			// fleet-wide.  The one-shot --upload path passes a nil
			// debouncer (no cross-cycle state) and tears down on the
			// single signal, matching its run-once semantics.
			shouldTeardown := true
			if igDisableDebounce != nil {
				shouldTeardown = igDisableDebounce.RecordDisabled()
			}
			if !shouldTeardown {
				log.Info("install-gate server-disabled signal observed; debouncing before teardown",
					slog.Int("threshold", debounceThreshold(igDisableDebounce)))
				logAudit(auditLog, "install_gate.disable_debounced", "")
				break
			}
			// Tear down host configs + persist a marker so an agent
			// restart between this and the next 200 doesn't re-write
			// configs from the local cache.
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
			// Any non-disable error breaks a disable streak: a transient
			// network failure is not evidence the server wants teardown.
			if igDisableDebounce != nil {
				igDisableDebounce.Reset()
			}
			log.Warn("install-gate refresh failed (using cached)", slog.String("err", err.Error()))
		case igMap != nil:
			// Healthy 200 — break any pending disable streak so a later
			// single disable blip starts counting from zero again.
			if igDisableDebounce != nil {
				igDisableDebounce.Reset()
			}
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
			// Persist the signed envelope for offline re-apply — but
			// NOT when it embeds cleartext registry credentials.  The
			// envelope is the verbatim signed bytes (auth tokens /
			// passwords included), so caching a credential-bearing map
			// would leave operator secrets at rest on the host.  We
			// re-fetch from the server next cycle instead (currentVersion
			// resets to 0 because nothing is cached).  Credential-free
			// maps still cache normally.
			if igMap.HasRegistryCredentials() {
				log.Info("install-gate map carries registry credentials; not caching envelope on disk")
			} else if err := scanner.SaveVerifiedInstallGateEnvelopeToFile(igCachePath, envelope); err != nil {
				log.Warn("failed to cache install-gate map", slog.String("err", err.Error()))
			}
			res, errs := installgate.Apply(igMap, installGateApplyOptions(agentCfg, installgate.MarkerFields{
				Version: igMap.Version,
				KeyID:   envelopeKeyID(envelope),
				Applied: time.Now().UTC(),
			}))
			// Writers have consumed the credentials — clear the cleartext
			// material from the in-memory map so it does not stay resident
			// for the remainder of this run.
			igMap.ZeroRegistryCredentials()
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
		default:
			// (nil, nil, nil): server returned no newer version (or a
			// non-error no-op).  This is a healthy outcome — reset any
			// pending disable streak so an isolated future disable blip
			// doesn't combine with stale counts toward teardown.
			if igDisableDebounce != nil {
				igDisableDebounce.Reset()
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

	// Drain cached scans from previous offline runs, strictly oldest-first,
	// looping across batches until the whole backlog is gone (see
	// drainCachedScans).  backlogEmpty reports whether the queue is now empty —
	// the fresh scan below is uploaded directly ONLY when it is, otherwise the
	// fresh scan is enqueued behind the backlog to preserve FIFO order on the
	// server (finding offline-5).
	backlogEmpty := drainCachedScans(ctx, client, scanCache, auditLog, log)

	logAudit(auditLog, "scan.started", fmt.Sprintf("hostname=%s", hostname))

	cfg := scanner.Config{
		ScanRoot:       agentCfg.Scanner.ScanRoot,
		MaxDepth:       agentCfg.Scanner.MaxDepth,
		MaxWorkers:     8,
		ScanContainers: agentCfg.Scanner.ScanContainers,
		// Container materialisation lands under the agent's disk-backed
		// data dir (never tmpfs) — see scanner.Config.DataDir.
		DataDir: dataDir,
	}
	if v := os.Getenv("SENTARI_SCAN_CONTAINERS"); v == "true" || v == "1" {
		cfg.ScanContainers = true
	}

	result, err := scanner.NewRunner(cfg).Run(ctx)
	if err != nil {
		logAudit(auditLog, "scan.failed", err.Error())
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

	logAudit(auditLog, "scan.completed", fmt.Sprintf("packages=%d containers=%d",
		len(result.Packages), len(result.ContainerTargets)))

	// Override scanner's local machine-id with the server-assigned UUID so the
	// server can match the scan to the registered device record.
	if serverDeviceID := comms.LoadDeviceID(certDir); serverDeviceID != "" {
		result.DeviceID = serverDeviceID
	}

	// Write local SBOM file if requested (useful for air-gapped deployments).
	// Format was validated at startup, so writeSBOMFile only has to dispatch.
	if sbomOutPath != "" {
		if sbomErr := writeSBOMFile(result, sbomOutPath, sbomFormat); sbomErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write SBOM to %s: %v\n", sbomOutPath, sbomErr)
		} else {
			fmt.Fprintf(os.Stderr, "SBOM (%s) written to %s\n", sbomFormat, sbomOutPath)
		}
	}

	// FIFO ordering (finding offline-5): if the offline backlog was NOT fully
	// drained above, the server has not yet seen the older queued scans.
	// Uploading this fresh (newest) scan directly now would land newest-before-
	// older and repeatedly regress the server's current-state projection as the
	// backlog catches up.  Enqueue the fresh scan behind the backlog instead so
	// it drains in strict chronological order on a later cycle.
	if !backlogEmpty {
		log.Info("offline backlog not fully drained; enqueuing fresh scan to preserve FIFO upload order",
			slog.Int("packages", len(result.Packages)))
		enqueueScanWithFallback(result, scanCache, auditLog, certDir)
		logAudit(auditLog, "scan.enqueued_behind_backlog", fmt.Sprintf("packages=%d", len(result.Packages)))
		return nil
	}

	if uploadErr := client.UploadScan(ctx, result); uploadErr != nil {
		// Cache locally for the next run (falling back to a JSON file if the
		// SQLite enqueue itself fails).
		enqueueScanWithFallback(result, scanCache, auditLog, certDir)
		logAudit(auditLog, "upload.failed", uploadErr.Error())
		return fmt.Errorf("upload: %w", uploadErr)
	}

	logAudit(auditLog, "upload.success", fmt.Sprintf("packages=%d", len(result.Packages)))

	// Off-host re-anchoring: ship the local append-only audit chain to the
	// server so a later on-device compromise cannot silently rewrite history
	// the server already witnessed (contract agent-audit-ship-v1). Best-effort
	// — failures keep the entries queued for the next cycle and never abort it.
	shipAuditLog(ctx, client, auditLog, result.DeviceID, log)

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

// drainDecision classifies how the cache-drain loop should react to a failed
// UploadScan.
type drainDecision int

const (
	// drainStop: transient failure (transport error, 5xx, 429) — stop
	// draining and keep the whole backlog queued for the next cycle.
	drainStop drainDecision = iota
	// drainMarkDead: permanent client-side rejection (non-retryable 4xx) —
	// mark this row dead and keep draining the rows behind it.
	drainMarkDead
)

// classifyDrainError decides the drain loop's reaction to an UploadScan error.
//
// Only a *comms.HTTPStatusError carrying a genuinely PAYLOAD-permanent 4xx marks
// the row dead: 400 (malformed), 413 (too large), 415 (unsupported media type),
// 422 (unprocessable) — the server will NEVER accept THIS payload no matter how
// often it is retried, so marking it dead lets the queue behind it drain instead
// of head-of-line-blocking forever.
//
// Every OTHER 4xx is treated as transient (drainStop): 401 (mTLS cert not
// forwarded by a proxy), 403 (rotated trusted-proxy secret, unknown/expired
// device cert, clock skew), 407 (proxy auth) and any unrecognized 4xx are
// auth/proxy/config STATE — recoverable once the operator fixes the environment.
// Marking those dead would destroy the whole offline backlog on a transient
// misconfiguration.  429 (retries exhausted), 5xx, and plain transport errors
// are likewise transient.  On drainStop the rows stay queued and the drain
// simply stops for this cycle.  Factored out of the loop so the classification
// is unit-testable without a live server.
func classifyDrainError(err error) drainDecision {
	var httpErr *comms.HTTPStatusError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusBadRequest, // 400
			http.StatusRequestEntityTooLarge, // 413
			http.StatusUnsupportedMediaType,  // 415
			http.StatusUnprocessableEntity:   // 422
			return drainMarkDead
		}
	}
	return drainStop
}

// scanUploader is the subset of *comms.Client the drain loop needs, so
// drainCachedScans can be unit-tested against a stub without a live server.
type scanUploader interface {
	UploadScan(ctx context.Context, result *scanner.ScanResult) error
}

// drainCache is the subset of *cache.Cache the drain loop needs.  Like
// scanUploader, it is an interface so drainCachedScans can be unit-tested
// against a stub — in particular one whose DequeuePending/PendingCount returns a
// corruption error, exercising the lazy-corruption recovery path (finding
// offline-1) without having to provoke a real torn SQLite page.  *cache.Cache
// satisfies it.
type drainCache interface {
	DequeuePending() ([]cache.CachedScan, int, error)
	MarkUploaded(queueID int64) error
	MarkFailedPermanent(queueID int64) error
	PendingCount() (int, error)
	PurgeUploaded(olderThan time.Duration) (int64, error)
	Reopen() (recovered bool, quarantinedPath string, err error)
}

// drainCachedScans uploads queued offline scans to the server in strict
// oldest-first (FIFO) order, looping across DequeuePending batches until the
// backlog is fully drained, the cycle context expires, or a transient failure
// stops the drain.  Permanently-rejected rows (non-retryable 4xx) are marked
// dead and the drain continues behind them; a transient failure (transport,
// 5xx, exhausted 429) stops the drain and leaves the remaining rows queued.
//
// It returns backlogEmpty=true only when the pending queue is now empty — every
// row was either uploaded or quarantined dead.  The caller uses that to decide
// whether the fresh scan may be uploaded directly (queue empty) or must be
// enqueued behind the backlog (queue not empty) to preserve server-side FIFO
// ordering.  Previously runUpload drained at most ONE 100-row batch per cycle
// and then always uploaded the fresh scan directly, so after a >100-scan outage
// the server saw newest-then-older and regressed its projection every cycle
// (finding offline-5).
func drainCachedScans(ctx context.Context, up scanUploader, scanCache drainCache, auditLog *audit.AuditLog, log *slog.Logger) (backlogEmpty bool) {
	totalDrained := 0
drainLoop:
	for ctx.Err() == nil {
		pending, quarantined, err := scanCache.DequeuePending()
		if err != nil {
			// SQLite surfaces data-page corruption LAZILY, on the read that
			// touches the damaged page — so a torn write in scan_queue can error
			// here every cycle forever, long after the cache opened cleanly.
			// Recover exactly as the startup path does: quarantine the corrupt
			// file aside and recreate an empty queue (the drain then resumes on
			// the next cycle).  A non-corruption read error is transient — just
			// log and retry next cycle without destroying the backlog.
			if dbhealth.IsCorruption(err) {
				recoverCorruptCacheDuringDrain(scanCache, auditLog, log, err)
			} else {
				log.Warn("failed to read cache", slog.String("err", err.Error()))
			}
			break
		}
		if len(pending) == 0 {
			// No USABLE rows in this batch.  Two very different situations:
			//   • quarantined > 0 — the batch consisted ENTIRELY of corrupt rows
			//     that DequeuePending just flipped to dead (uploaded = 2).  Good
			//     pending rows may sit behind them, so keep draining: the next
			//     batch skips the now-dead rows (id-ordered, uploaded = 0 only)
			//     and advances.  Because only durably-marked rows are counted,
			//     each such continue makes strict forward progress and cannot
			//     spin (finding offline-1).
			//   • quarantined == 0 — there are genuinely no more pending rows
			//     (or a quarantine write failed, which we retry next cycle).
			//     Stop the drain.
			if quarantined > 0 {
				log.Warn("cache drain: batch was entirely corrupt; quarantined and continuing to next batch",
					slog.Int("quarantined", quarantined))
				logAudit(auditLog, "cache.drain.quarantined", fmt.Sprintf("quarantined=%d", quarantined))
				continue
			}
			break // Backlog genuinely drained.
		}
		for _, cached := range pending {
			// Stop promptly on shutdown / budget expiry mid-batch; the
			// undrained rows stay pending for the next cycle.
			if ctx.Err() != nil {
				break drainLoop
			}
			if uploadErr := up.UploadScan(ctx, cached.Result); uploadErr != nil {
				if classifyDrainError(uploadErr) == drainMarkDead {
					// Server permanently rejected this payload (non-retryable
					// 4xx).  Mark it dead so it stops head-of-line-blocking the
					// queue, and keep draining the rows behind it.
					logAudit(auditLog, "cache.drain.dead", fmt.Sprintf("queued=%d err=%v", cached.QueueID, uploadErr))
					log.Warn("cached scan permanently rejected by server; marking dead and continuing drain",
						slog.Int64("queue_id", cached.QueueID),
						slog.String("err", uploadErr.Error()),
					)
					if markErr := scanCache.MarkFailedPermanent(cached.QueueID); markErr != nil {
						// Could not quarantine it — breaking avoids an infinite
						// loop re-dequeuing the same undead row every iteration.
						log.Warn("failed to mark cached scan permanently failed; stopping drain",
							slog.Int64("queue_id", cached.QueueID),
							slog.String("err", markErr.Error()),
						)
						break drainLoop
					}
					continue
				}
				logAudit(auditLog, "cache.drain.failed", fmt.Sprintf("queued=%d err=%v", cached.QueueID, uploadErr))
				log.Warn("failed to upload cached scan",
					slog.Int64("queue_id", cached.QueueID),
					slog.String("err", uploadErr.Error()),
				)
				break drainLoop // Transient (transport/5xx/429); keep the rest queued.
			}
			// AT-LEAST-ONCE DELIVERY (finding offline-3).  The upload above
			// succeeded server-side, but a cache-write failure here leaves the
			// row pending (uploaded = 0), so the next cycle re-dequeues and
			// re-uploads it: delivery is at-least-once, not exactly-once.  There
			// is no distributed transaction spanning the HTTP POST and the local
			// SQLite mark, so this window is inherent to the queue design.  It is
			// SAFE because the server dedups the re-delivery on the stable key
			// (device_id, scanned_at, content-hash): see
			// sentari/server/api/v1/agent.py `_find_duplicate_scan`
			// (scoped by ScanResult.device_id + ScanResult.scanned_at, confirmed
			// by _scan_content_hash) and its call site in `upload_scan`.  The
			// agent relies specifically on scanned_at being stamped ONCE at scan
			// time (scanner.Run: `ScannedAt: time.Now().UTC()`) and preserved
			// byte-for-byte across the cache round-trip — EnqueueScan persists the
			// whole ScanResult as scan_json and DequeuePendingBatch json.Unmarshals
			// it back, so a re-uploaded queued scan carries the IDENTICAL
			// scanned_at and the server's dedup collapses it to the original.
			if markErr := scanCache.MarkUploaded(cached.QueueID); markErr != nil {
				// Could not advance the cursor — breaking avoids re-uploading
				// the same row every iteration.  It retries next cycle and the
				// server dedups the duplicate delivery (see the at-least-once note
				// above).  Emit a clear warning + audit entry so the intentional
				// re-delivery is explainable in the tamper-evident trail rather
				// than looking like an unexplained duplicate scan.
				log.Warn("upload succeeded but mark-uploaded failed; scan will re-deliver next cycle (server dedups on device_id+scanned_at+content-hash); stopping drain",
					slog.Int64("queue_id", cached.QueueID),
					slog.Time("scanned_at", cached.Result.ScannedAt),
					slog.String("err", markErr.Error()),
				)
				logAudit(auditLog, "cache.drain.mark_uploaded_failed", fmt.Sprintf(
					"queued=%d scanned_at=%s err=%v (upload succeeded; will re-deliver, server dedups on device_id+scanned_at+content-hash)",
					cached.QueueID, cached.Result.ScannedAt.Format(time.RFC3339), markErr))
				break drainLoop
			}
			totalDrained++
		}
	}

	if totalDrained > 0 {
		logAudit(auditLog, "cache.drain.success", fmt.Sprintf("uploaded=%d", totalDrained))
		// Purge terminal entries older than 7 days to bound disk growth; a
		// week's retention allows forensic inspection of recently-drained rows.
		if purged, purgeErr := scanCache.PurgeUploaded(7 * 24 * time.Hour); purgeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cache purge failed: %v\n", purgeErr)
		} else if purged > 0 {
			fmt.Fprintf(os.Stderr, "Purged %d old cache entries\n", purged)
		}
	}

	// Authoritative FIFO signal: the queue is only "empty" when no pending rows
	// remain.  On a read error, conservatively report a non-empty backlog so the
	// fresh scan is enqueued (never uploaded ahead of possibly-undrained rows).
	remaining, err := scanCache.PendingCount()
	if err != nil {
		// A lazily-surfaced corruption on the count read gets the same recovery
		// as the dequeue path; otherwise it is a transient read error.
		if dbhealth.IsCorruption(err) {
			recoverCorruptCacheDuringDrain(scanCache, auditLog, log, err)
		} else {
			log.Warn("failed to count pending after drain; treating backlog as non-empty", slog.String("err", err.Error()))
		}
		return false
	}
	return remaining == 0
}

// recoverCorruptCacheDuringDrain reacts to a corruption-class error from a cache
// read (DequeuePending/PendingCount) during the drain by re-running the resilient
// open via Cache.Reopen: the corrupt file is quarantined aside, a fresh empty
// queue replaces it, and a loud "cache.recreated" audit entry records that any
// un-drained offline scans in the corrupt file are gone — mirroring the startup
// OpenResilient recovery so a lazily-discovered corruption cannot wedge the drain
// forever.  Best-effort: a failed re-open is logged and the daemon retries on the
// next cycle; a transient (non-recovered) re-open outcome writes no audit entry.
func recoverCorruptCacheDuringDrain(scanCache drainCache, auditLog *audit.AuditLog, log *slog.Logger, cause error) {
	log.Error("cache: on-disk queue corruption detected during drain; quarantining and recreating",
		slog.String("err", cause.Error()))
	recovered, quarantinedPath, reErr := scanCache.Reopen()
	if reErr != nil {
		log.Error("cache: failed to recreate corrupt queue during drain; will retry next cycle",
			slog.String("err", reErr.Error()))
		return
	}
	if recovered {
		logAudit(auditLog, "cache.recreated", fmt.Sprintf("corrupt_db_quarantined=%s", quarantinedPath))
		log.Error("cache: corrupt on-disk queue quarantined and recreated; pending offline scans in the corrupt file are lost",
			slog.String("quarantined", quarantinedPath))
	}
}

// enqueueScanWithFallback stores result in the local SQLite queue and, only if
// that write itself fails, writes the scan to a last-resort JSON fallback file
// so the data is not lost.  Shared by the upload-failed path and the FIFO
// backlog-present path in runUpload.
func enqueueScanWithFallback(result *scanner.ScanResult, scanCache *cache.Cache, auditLog *audit.AuditLog, certDir string) {
	if ev, cacheErr := scanCache.EnqueueScan(result); cacheErr == nil {
		// A backlog-cap eviction silently drops the oldest inventory snapshots.
		// Record it in the tamper-evident audit chain so the loss is not
		// invisible (every other queue event is audited).
		if ev.Count > 0 {
			logAudit(auditLog, "cache.evicted", fmt.Sprintf(
				"evicted=%d oldest_scanned_at=%s newest_scanned_at=%s reason=%s",
				ev.Count, ev.OldestScannedAt, ev.NewestScannedAt, ev.Reason))
		}
		return
	} else {
		fmt.Fprintf(os.Stderr, "Warning: failed to cache scan in SQLite: %v\n", cacheErr)
	}
	// Last resort: write scan to a JSON file so the data is not lost.  The file
	// can be manually imported or inspected by operators.
	fallbackDir := filepath.Dir(certDir)
	// Bound the fallback files first so they cannot accumulate unboundedly (they
	// are never auto-re-ingested).  Prune to maxFallbackFiles-1 so this new
	// write leaves at most maxFallbackFiles behind.
	if pruneErr := pruneFallbackFiles(fallbackDir, maxFallbackFiles-1); pruneErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to prune old fallback files: %v\n", pruneErr)
	}
	fallbackPath := filepath.Join(fallbackDir, fmt.Sprintf("scan-fallback-%d.json", time.Now().Unix()))
	if fbData, fbErr := json.Marshal(result); fbErr == nil {
		if writeErr := os.WriteFile(fallbackPath, fbData, 0600); writeErr == nil {
			fmt.Fprintf(os.Stderr, "Scan saved to fallback file: %s\n", fallbackPath)
			logAudit(auditLog, "cache.fallback", fmt.Sprintf("path=%s", fallbackPath))
		} else {
			fmt.Fprintf(os.Stderr, "CRITICAL: scan data lost — cache and fallback file write both failed: %v\n", writeErr)
		}
	}
}

// maxFallbackFiles bounds how many scan-fallback-*.json files may accumulate
// in the data dir.  The fallback JSON is the last resort when BOTH the upload
// and the SQLite cache write fail; the files are never auto-re-ingested, so
// without a cap they grow unbounded.  The newest ones are the most useful for
// recovery, so the oldest are pruned first.
const maxFallbackFiles = 5

// pruneFallbackFiles deletes the oldest scan-fallback-*.json files in dir so
// that at most `keep` remain.  Ordering is by file modification time (oldest
// first), falling back to lexical name order when a stat fails.  Best-effort:
// returns the first delete/glob error for the caller to log, but is otherwise
// non-fatal.
func pruneFallbackFiles(dir string, keep int) error {
	matches, err := filepath.Glob(filepath.Join(dir, "scan-fallback-*.json"))
	if err != nil {
		return err
	}
	if keep < 0 {
		keep = 0
	}
	if len(matches) <= keep {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool {
		fi, ei := os.Stat(matches[i])
		fj, ej := os.Stat(matches[j])
		if ei == nil && ej == nil {
			return fi.ModTime().Before(fj.ModTime())
		}
		return matches[i] < matches[j]
	})
	toDelete := len(matches) - keep
	var firstErr error
	for i := 0; i < toDelete; i++ {
		if rmErr := os.Remove(matches[i]); rmErr != nil && firstErr == nil {
			firstErr = rmErr
		}
	}
	return firstErr
}
