//go:build enterprise

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
)

// cycleParams carries the per-host operational parameters that stay constant
// across every serve cycle: the host identity, the optional local-SBOM output
// target (path + already-validated format), and the resolved cert / data
// directories.  Grouped into one value so the run → serve → upload call chain
// passes a single struct instead of the same five consecutive string arguments
// threaded through each signature (finding quality-2).
type cycleParams struct {
	hostname    string
	sbomOutPath string
	sbomFormat  string
	certDir     string
	dataDir     string
}

// defaultCycleBudget is the absolute ceiling on how long a single
// serve cycle (drain + scan + upload + renew + config-poll) may run
// before its context deadline fires.  Chosen well above a healthy
// cycle (seconds to a couple of minutes on a real fleet device) yet
// low enough that a wedged walk is surfaced the same day rather than
// silently pinning a worker forever.
const defaultCycleBudget = 45 * time.Minute

// maxCycleBudget caps how far the per-cycle deadline may be escalated after
// repeated budget overruns.  8h is well past any healthy scan yet short enough
// that a genuinely wedged cycle is still surfaced within a working shift.  A
// base floor larger than this (a multi-hour scan interval) legitimately wins —
// see cycleBudgetState.budget.
const maxCycleBudget = 8 * time.Hour

// cycleBudget returns the BASE per-cycle deadline: max(interval,
// defaultCycleBudget).
//
// This is a FLOOR, not a ceiling.  The earlier min(interval, ...) semantics
// turned "scan slower than the interval" into permanent zero-data: an operator
// pushing the interval down to 60s while a real fleet host takes 6 minutes to
// walk its filesystem meant every cycle's deadline fired mid-scan and NOTHING
// ever uploaded, forever.  Flooring the budget at defaultCycleBudget guarantees
// a cycle always has at least ~45 minutes to complete regardless of how tight
// the interval is; a longer interval raises the floor further (a 3h interval
// gets a 3h budget).  Cycles piling up under a tight interval is a far milder
// failure than never producing data.  Factored out so the choice is
// unit-testable without standing up the whole daemon loop.
func cycleBudget(interval time.Duration) time.Duration {
	if interval > defaultCycleBudget {
		return interval
	}
	return defaultCycleBudget
}

// cycleBudgetState tracks consecutive per-cycle budget overruns so a host whose
// scans genuinely need longer than the base budget escalates toward completion
// instead of being killed identically every cycle.  Held for the daemon
// lifetime by serveLoop; not safe for concurrent use (the loop is single-
// threaded).
type cycleBudgetState struct {
	consecutiveOverruns int
}

// budget returns the deadline for the upcoming cycle: the base floor
// (cycleBudget(interval)) doubled once per consecutive prior overrun, capped at
// maxCycleBudget — but never below the base floor (so a multi-hour interval
// whose floor already exceeds the cap keeps its floor).  A wedged host thus
// gets 45m, then 90m, 180m, ... up to 8h across successive stuck cycles rather
// than the same doomed 45m every time; the first cycle that completes within
// budget calls recordSuccess and drops the escalation back to the base.
func (s *cycleBudgetState) budget(interval time.Duration) time.Duration {
	base := cycleBudget(interval)
	ceiling := maxCycleBudget
	if base > ceiling {
		ceiling = base
	}
	b := base
	for i := 0; i < s.consecutiveOverruns; i++ {
		if b >= ceiling {
			break
		}
		b *= 2
	}
	if b > ceiling {
		b = ceiling
	}
	return b
}

// recordOverrun bumps the consecutive-overrun count so the NEXT cycle's budget
// escalates.  Called when a cycle exceeds its deadline while the daemon is not
// shutting down.
func (s *cycleBudgetState) recordOverrun() { s.consecutiveOverruns++ }

// recordSuccess resets the escalation after any cycle that finished within its
// budget, so a single slow cycle does not permanently inflate the deadline.
func (s *cycleBudgetState) recordSuccess() { s.consecutiveOverruns = 0 }

// runServe runs the agent as a daemon, uploading scans on a configurable schedule.
// Listens for SIGINT/SIGTERM for graceful shutdown: finishes the current cycle
// before exiting.
//
// On each cycle the agent polls the server for configuration updates. If the
// server returns a different scan_interval, the agent applies it immediately
// for the next sleep. This lets administrators change the scan frequency via the
// system_config table without restarting agents.
func runServe(client *comms.Client, auditLog *audit.AuditLog, scanCache *cache.Cache, agentCfg config.AgentConfig, cp cycleParams, renewCfg renewClientConfig, bp bootstrapParams) {
	// Root context cancelled on SIGINT/SIGTERM.  Every cycle's context is
	// derived from this so an in-flight retry/backoff sleep inside
	// runUpload → doRequest (which honours ctx.Done()) aborts promptly on
	// shutdown rather than running the full backoff schedule to completion.
	//
	// We use a manual signal channel rather than signal.NotifyContext so the
	// shutdown audit entry can record WHICH signal was received (SIGTERM from
	// systemd/launchd stop vs SIGINT from an operator console) — meaningful
	// forensic context in the append-only audit log.
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	// Buffered so the handler records the signal before cancelling; the
	// shutdown branch reads it after rootCtx.Done() (happens-after cancel).
	shutdownSig := make(chan os.Signal, 1)
	go watchSignals(sigCh, shutdownSig, cancel, os.Exit, slog.Default())

	// shutdownReason labels the audit entry with the signal that triggered
	// teardown.  Read after rootCtx.Done() (happens-after cancel), so the
	// value is already present.  The Windows SCM path (service_windows.go)
	// drives the same rootCtx cancellation and supplies its own reason, so
	// both console and service teardown share serveLoop's one exit route.
	shutdownReason := func() string {
		select {
		case s := <-shutdownSig:
			return s.String()
		default:
			return "unknown"
		}
	}

	serveLoop(rootCtx, shutdownReason, client, auditLog, scanCache, agentCfg, cp, renewCfg, bp)
}

// watchSignals implements the daemon's two-stage termination handling.
//
// The FIRST SIGINT/SIGTERM triggers a GRACEFUL shutdown: the signal is
// forwarded on gotSignal (so the agent.shutdown audit entry can record WHICH
// signal arrived) and cancel() unwinds the serve loop, letting the current
// cycle finish or abort its cancellable work.  This path is unchanged.
//
// The escalation is the SECOND delivery.  Because signal.Notify stays
// registered for the whole runServe lifetime, the OS default terminate
// disposition is disabled process-wide — so if the graceful path then wedges
// (stuck upload, hard/non-`intr` NFS mount), a second Ctrl-C / SIGTERM would
// otherwise be silently swallowed and the operator would be left with no
// force-quit short of SIGKILL.  Instead the second signal forces a hard,
// deterministic exit(1) with a loud log line, so an impatient operator always
// has a way out and the behaviour is predictable rather than a hang.
//
// Injectable sigCh / gotSignal / cancel / exit / log keep the two-signal
// decision unit-testable without delivering real OS signals or terminating the
// test process.
func watchSignals(sigCh <-chan os.Signal, gotSignal chan<- os.Signal, cancel context.CancelFunc, exit func(int), log *slog.Logger) {
	// First signal: graceful shutdown. Record it, then cancel the root ctx.
	s, ok := <-sigCh
	if !ok {
		return
	}
	gotSignal <- s
	cancel()

	// Second signal: hard exit. The registration above means the OS won't
	// terminate us on its own, so make the force-quit explicit and loud.
	s2, ok := <-sigCh
	if !ok {
		return
	}
	if log != nil {
		log.Error("forced shutdown: second signal received while shutting down gracefully; exiting immediately (in-flight work abandoned)",
			slog.String("signal", s2.String()),
		)
	}
	exit(1)
}

// serveLoop is the OS-agnostic daemon body: the drain → scan → upload → renew →
// config-poll cycle repeated until rootCtx is cancelled.  It is shared verbatim
// by the console entry (runServe, which cancels rootCtx on SIGINT/SIGTERM) and
// the Windows SCM handler (service_windows.go, which cancels it on a Stop /
// Shutdown control request), so graceful teardown behaves identically under
// both.  shutdownReason is invoked once at teardown to label the audit entry
// with what triggered it.
func serveLoop(rootCtx context.Context, shutdownReason func() string, client *comms.Client, auditLog *audit.AuditLog, scanCache *cache.Cache, agentCfg config.AgentConfig, cp cycleParams, renewCfg renewClientConfig, bp bootstrapParams) {
	scanInterval := time.Duration(agentCfg.Scanner.Interval) * time.Second
	if scanInterval <= 0 {
		scanInterval = 3600 * time.Second
	}

	// One debouncer for the whole daemon lifetime so the consecutive-
	// disable count persists across cycles (see InstallGateDisableDebouncer).
	igDisableDebounce := comms.NewInstallGateDisableDebouncer()

	// Per-cycle budget escalation state, held for the daemon lifetime so a host
	// whose scans genuinely need longer than the base budget ramps its deadline
	// up across consecutive overruns instead of being killed identically every
	// cycle.  Reset on the first cycle that completes within budget.
	budgetState := &cycleBudgetState{}

	for {
		// Bail before starting a cycle if shutdown was already signalled.
		if rootCtx.Err() != nil {
			break
		}

		// Per-cycle deadline: min(interval, defaultCycleBudget), derived
		// from the cancellable root so both SIGTERM (shutdown) and the
		// budget timeout abort the cycle's cancellable work — outbound
		// retries, the ctx-aware filesystem walk, container sub-scans.
		//
		// Honesty caveat: this bounds everything *cancellable*.  A hard
		// (non-`intr`) NFS mount blocked in an uninterruptible syscall
		// won't unblock on ctx cancel — the goroutine stays wedged in
		// the kernel.  Mount avoidance is the real defence there
		// (pathfilter cloud-skip + --exclude-network-paths); this
		// deadline's job is to stop everything that CAN stop and to
		// surface the wedge loudly (log + audit) so an operator sees a
		// cycle that blew its budget instead of a silently hung daemon.
		budget := budgetState.budget(scanInterval)
		cycleCtx, cycleCancel := context.WithTimeout(rootCtx, budget)

		// Fresh request_id per cycle, derived from the deadline-bearing
		// context.  One scan, one CVE-correlation wave, one
		// alert-delivery fan-out — all join on this ID.
		ctx := logging.WithRequestID(cycleCtx, logging.NewRequestID())
		log := logging.LoggerFromContext(ctx)
		cycleStart := time.Now()

		// Cycle-start cache health/recovery hook.  A prior cycle's Cache.Reopen
		// may have closed the handle but failed to swap a fresh one in for a
		// TRANSIENT reason (ENOSPC on a near-full air-gap disk — the very case the
		// byte caps fight — EACCES, a lock).  Nothing else re-opens the cache
		// (it is opened once at startup and held for the daemon lifetime), so
		// without this hook every subsequent cycle would fail on a dead handle
		// and silently lose scans for the rest of the offline window.  Retry the
		// re-open before the drain so the daemon self-heals in-process once the
		// condition clears — no restart (findings offline-1/2).
		ensureCacheOpen(scanCache, auditLog, log)

		if err := runUpload(ctx, client, auditLog, scanCache, agentCfg, cp, igDisableDebounce); err != nil {
			log.Error("cycle error", slog.String("err", err.Error()))
		}

		// Renew the device cert well before expiry, over the current mTLS
		// client.  Cheap when outside the window (one local cert parse); on a
		// successful renewal the client is rebuilt in-memory so subsequent
		// cycles use the new identity.  Always non-fatal.
		client = maybeRenewCertificate(ctx, client, renewCfg, cp.certDir, cp.hostname, auditLog)

		// Cert-expiry recovery (finding offline-7): if renewal never succeeded
		// and the device cert has actually LAPSED (an outage longer than its
		// remaining validity), re-enroll via the bootstrap token — or, with no
		// token, log a single actionable error this cycle instead of a per-
		// request TLS flood.  No-op (one local cert parse) while the cert is
		// valid.  Runs after renewal so the 30-day pre-expiry window is handled
		// by the cheaper renew path first.
		client = maybeReenrollOnExpiredCert(ctx, client, bp, renewCfg, cp.hostname, auditLog)

		// Poll server for configuration updates (scan interval, scan root, etc.).
		if serverCfg, err := client.PollConfig(ctx); err == nil {
			if serverCfg.ScanInterval > 0 {
				clampedSecs := clampScanIntervalSeconds(serverCfg.ScanInterval)
				if clampedSecs != serverCfg.ScanInterval {
					log.Warn("clamping out-of-range scan_interval from server",
						slog.Int("requested", serverCfg.ScanInterval),
						slog.Int("applied", clampedSecs),
					)
				}
				newInterval := time.Duration(clampedSecs) * time.Second
				if newInterval != scanInterval {
					log.Info("scan interval changed",
						slog.Duration("old", scanInterval),
						slog.Duration("new", newInterval),
					)
					logAudit(auditLog, "config.updated", fmt.Sprintf("scan_interval=%d", clampedSecs))
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
				clampedDepth := clampMaxDepth(serverCfg.MaxDepth)
				if clampedDepth != serverCfg.MaxDepth {
					log.Warn("clamping out-of-range max_depth from server",
						slog.Int("requested", serverCfg.MaxDepth),
						slog.Int("applied", clampedDepth),
					)
				}
				agentCfg.Scanner.MaxDepth = clampedDepth
			}
		} else {
			log.Warn("config poll failed (using cached interval)",
				slog.Duration("interval", scanInterval),
				slog.String("err", err.Error()),
			)
		}

		// Cycle deadline check: the cycle context's timeout fired while
		// the root context is still live (i.e. this is a budget breach,
		// not a shutdown).  Surface it loudly + in the append-only audit
		// log so a wedged cycle is visible.  The cancellable work has
		// already been signalled to stop via the context; anything still
		// running is stuck in an uninterruptible syscall (see the budget
		// comment above).
		if cycleCtx.Err() == context.DeadlineExceeded && rootCtx.Err() == nil {
			elapsed := time.Since(cycleStart).Round(time.Second)
			// Escalate the NEXT cycle's budget so a host that genuinely needs
			// longer than the base budget ramps toward completion instead of
			// being killed identically forever.
			budgetState.recordOverrun()
			nextBudget := budgetState.budget(scanInterval)
			log.Error("scan cycle exceeded its budget; cancelled all cancellable work (a hard-mount wedge may persist)",
				slog.Duration("budget", budget),
				slog.Duration("elapsed", elapsed),
				slog.Duration("next_budget", nextBudget),
			)
			logAudit(auditLog, "scan.cycle_budget_exceeded",
				fmt.Sprintf("budget=%s elapsed=%s next_budget=%s", budget, elapsed, nextBudget))
		} else if rootCtx.Err() == nil {
			// Cycle finished within its budget — clear any escalation so a
			// single slow cycle does not permanently inflate the deadline.
			budgetState.recordSuccess()
		}
		// Release the cycle context before sleeping — the sleep waits on
		// rootCtx, not this per-cycle deadline.
		cycleCancel()

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
		case <-rootCtx.Done():
			sleepTimer.Stop()
			sigName := shutdownReason()
			log.Info("shutting down gracefully", slog.String("signal", sigName))
			logAudit(auditLog, "agent.shutdown", "signal="+sigName)
			return
		case <-sleepTimer.C:
			// Next cycle.
		}
	}
}

// cacheReopener is the subset of *cache.Cache the cycle-start health hook needs,
// so ensureCacheOpen can be unit-tested against a stub without provoking a real
// transient SQLite open failure.  *cache.Cache satisfies it.
type cacheReopener interface {
	NeedsReopen() bool
	Reopen() (recovered bool, quarantinedPath string, err error)
}

// ensureCacheOpen is the cycle-start cache health/recovery hook.  If the cache
// handle is in a closed/needs-reopen state — a prior Cache.Reopen closed the old
// handle but could not swap a fresh one in for a transient reason (ENOSPC on a
// near-full air-gap disk, EACCES, a lock) — it retries OpenResilient via Reopen
// before the drain:
//
//   - success (backlog preserved, or corrupt file quarantined + a fresh queue
//     created): log + write a `cache.reopened` audit entry so the recovery is
//     visible in the tamper-evident trail, and return true (cache healthy).
//   - continued failure: emit a LOUD operator warning + a `cache.wedged` audit
//     entry EACH cycle so the degraded state (silent scan loss risk) is not
//     invisible, and return false.  The daemon does NOT exit — a full disk would
//     restart-loop — it self-heals in-process on a later cycle once space frees.
//
// A healthy cache (NeedsReopen == false) is a no-op returning true.  Factored out
// of serveLoop so the recovery decision is unit-testable without the daemon loop.
func ensureCacheOpen(c cacheReopener, auditLog *audit.AuditLog, log *slog.Logger) (healthy bool) {
	if !c.NeedsReopen() {
		return true
	}
	recovered, quarantinedPath, err := c.Reopen()
	if err != nil {
		log.Error("cache: offline queue is WEDGED — handle closed after a prior transient re-open failure "+
			"(e.g. ENOSPC on a near-full disk); retrying every cycle until the condition clears. "+
			"Scans this cycle may fall back to disk or be lost.",
			slog.String("err", err.Error()))
		logAudit(auditLog, "cache.wedged", fmt.Sprintf("err=%v", err))
		return false
	}
	if recovered {
		log.Warn("cache: offline queue re-opened after a prior failure; corrupt file quarantined and a fresh empty queue created",
			slog.String("quarantined", quarantinedPath))
		logAudit(auditLog, "cache.reopened", fmt.Sprintf("corrupt_db_quarantined=%s", quarantinedPath))
	} else {
		log.Info("cache: offline queue re-opened after a prior transient failure; backlog preserved")
		logAudit(auditLog, "cache.reopened", "backlog_preserved")
	}
	return true
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
