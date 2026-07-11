package containers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Default caps from the Sprint-17 plan §6 Phase C task 8.
const (
	defaultMaxContainersPerCycle = 100
	defaultPerContainerTimeout   = 60 * time.Second
)

// staleTempReapAge bounds how old a leftover materialisation temp dir
// must be before the startup reaper reclaims it.  A live scratch dir's
// on-disk lifetime is bounded by the per-container timeout (default 60s)
// plus its sub-scan, so any dir whose mtime is older than this is
// certainly orphaned by a process that died before its deferred cleanup
// ran.  Deliberately kept an order of magnitude above the per-container
// ceiling so a *concurrent* scan cycle sharing the same DataDir never
// has an in-flight dir falsely reaped out from under it.
const staleTempReapAge = 1 * time.Hour

// containerTempPrefix is the os.MkdirTemp pattern prefix for the
// per-target scratch trees; the reaper matches on it so it never
// touches a dir it didn't create.
const containerTempPrefix = "sentari-container-"

// ScanAndAppend runs the full container-scan phase on top of an
// already-populated host ScanResult.  It:
//
//  1. Discovers containers across every supported runtime.
//  2. Records every discovered target (runtime / image / name /
//     layer count) on result.ContainerTargets, regardless of
//     whether we end up sub-scanning its content.  Useful to the
//     dashboard for "what's on this host" visibility even when
//     the agent has capped out its per-cycle budget.
//  3. For each target (up to MaxContainersPerCycle), materialises
//     the merged rootfs to a temp dir, runs a sub-Runner against
//     it with the baseCfg's scanner settings (minus ScanRoot,
//     which is overridden to the temp dir), and merges the
//     resulting records back into “result“ after decorating
//     them with ContainerImageID / ContainerID / etc.
//  4. Each target's sub-scan runs under a per-container context
//     deadline so a single bad image can't stall the whole phase.
//  5. Panic recovery per target — matches the Sprint-15 pattern
//     already used in Runner.scanEnvironment.
//
// When ctx is cancelled the loop exits early; partial results
// already merged into “result“ are preserved.  ScanErrors are
// appended (never fatal) — the host scan is already done.
//
// Caller is responsible for setting baseCfg.ScanContainers; this
// function honours it but does not enforce feature-flag semantics.
func ScanAndAppend(ctx context.Context, baseCfg scanner.Config, result *scanner.ScanResult) {
	if result == nil {
		return
	}
	// Container records are appended after the host scan's own
	// normalisation pass, so canonicalise their paths too (idempotent —
	// the merged-rootfs walker already emits forward slashes).
	defer scanner.NormalizePaths(result)

	// Reclaim scratch trees orphaned by a previous run that died
	// uncleanly (kill -9, panic, power loss) before its deferred
	// os.RemoveAll could fire.  Done at phase startup, before we
	// create any new temp dirs, so <DataDir>/container-scan can't grow
	// unboundedly across crashes.  No-op when DataDir is unset (bare
	// OSS one-shot runs fall back to os.TempDir(), which the OS reaps).
	if baseCfg.DataDir != "" {
		reapStaleContainerTemp(filepath.Join(baseCfg.DataDir, "container-scan"), time.Now().UTC(), result)
	}

	s := NewScanner(Config{})
	targets, derrs := s.DiscoverTargets(ctx)
	result.Errors = append(result.Errors, derrs...)

	// Record a summary for every target we found, even the ones we
	// may decide to skip due to caps below.  Operators see "108
	// containers, 100 scanned, 8 skipped" rather than "100
	// containers and a silent truncation."
	for _, t := range targets {
		result.ContainerTargets = append(result.ContainerTargets, scanner.ContainerTargetSummary{
			Runtime:       string(t.Runtime),
			ImageID:       t.ImageID,
			ImageTags:     t.ImageTags,
			ContainerID:   t.ContainerID,
			ContainerName: t.ContainerName,
			LayerCount:    len(t.MergedRootFS.Layers),
		})
	}

	maxN := baseCfg.MaxContainersPerCycle
	if maxN <= 0 {
		maxN = defaultMaxContainersPerCycle
	}
	perTimeout := baseCfg.PerContainerTimeout
	if perTimeout <= 0 {
		perTimeout = defaultPerContainerTimeout
	}

	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			// Cancelled from above — stop sub-scanning, keep what
			// we have.  No ScanError: the cancellation is the
			// signal already.
			return
		}
		if i >= maxN {
			// Cap hit.  One summarising error covers the skip so
			// operators can grep for it without being flooded.
			result.Errors = append(result.Errors, scanner.ScanError{
				Path:      "container-scan",
				EnvType:   "container",
				Error:     fmt.Sprintf("container-scan cap reached (max=%d); %d targets skipped", maxN, len(targets)-i),
				Timestamp: time.Now().UTC(),
			})
			break
		}
		scanOneTarget(ctx, t, baseCfg, perTimeout, result)
	}
}

// reapStaleContainerTemp removes orphaned scratch trees left under
// <DataDir>/container-scan by a previous run that died uncleanly before
// its per-target `defer os.RemoveAll(tmp)` could fire.  Without this the
// data dir grows unboundedly across crashes — each aborted run leaks one
// sentari-container-* dir that nothing ever reclaims.
//
// Safety model: these dirs are single-run scratch — no live process
// depends on a prior run's tree — so reclaiming a truly orphaned one is
// always safe.  The only hazard is a *concurrent* scan cycle on the same
// DataDir whose scratch dir is still in use.  We guard against that with
// an mtime-age heuristic: a dir is reaped only if it (a) matches our own
// containerTempPrefix (never reap a dir we didn't create) AND (b) has not
// been modified within staleTempReapAge (1h), which is far longer than
// any live dir's write window (bounded by the per-container timeout).  A
// concurrent run's active dir therefore always looks "fresh" and is
// skipped.  Every failure is a non-fatal ScanError; a partial reclaim
// beats none, and the phase proceeds regardless.
func reapStaleContainerTemp(dir string, now time.Time, result *scanner.ScanResult) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// No prior container-scan dir — nothing to reclaim.
			return
		}
		result.Errors = append(result.Errors, scanner.ScanError{
			Path:      dir,
			EnvType:   "container",
			Error:     fmt.Sprintf("reap stale container temp: read dir: %v", err),
			Timestamp: now,
		})
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), containerTempPrefix) {
			// Not one of ours — leave it strictly alone.
			continue
		}
		info, infoErr := e.Info()
		if infoErr != nil {
			// Vanished between ReadDir and Info (a concurrent reaper or
			// the owning run cleaned it) — nothing to do.
			continue
		}
		if now.Sub(info.ModTime()) < staleTempReapAge {
			// Too fresh: may belong to a concurrent live scan cycle.
			continue
		}
		full := filepath.Join(dir, e.Name())
		if rmErr := os.RemoveAll(full); rmErr != nil {
			result.Errors = append(result.Errors, scanner.ScanError{
				Path:      full,
				EnvType:   "container",
				Error:     fmt.Sprintf("reap stale container temp: %v", rmErr),
				Timestamp: now,
			})
		}
	}
}

// scanOneTarget runs the sub-scan for a single ContainerTarget,
// safely appending its results to the parent “result“.  Wrapped
// so a panic or timeout on one target never aborts the loop.
func scanOneTarget(
	ctx context.Context,
	t ContainerTarget,
	baseCfg scanner.Config,
	perTimeout time.Duration,
	result *scanner.ScanResult,
) {
	defer func() {
		if rec := recover(); rec != nil {
			result.Errors = append(result.Errors, scanner.ScanError{
				Path:      containerPathID(t),
				EnvType:   "container",
				Error:     fmt.Sprintf("container scan panic: %v", rec),
				Timestamp: time.Now().UTC(),
			})
		}
	}()

	tctx, cancel := context.WithTimeout(ctx, perTimeout)
	defer cancel()

	// Materialise under the agent's data dir, not os.TempDir(): on
	// modern distros /tmp is a tmpfs (RAM), so a large image extracted
	// there would balloon memory rather than use the agent's
	// disk-backed state volume.  Bare OSS one-shot runs (`--scan`) leave
	// DataDir empty and fall back to os.TempDir() — acceptable for a
	// non-daemon diagnostic.
	tmpBase := os.TempDir()
	if baseCfg.DataDir != "" {
		dir := filepath.Join(baseCfg.DataDir, "container-scan")
		if mkErr := os.MkdirAll(dir, 0o700); mkErr == nil {
			tmpBase = dir
		} else {
			// Data dir unwritable (read-only rootfs, perms) — fall back
			// to the system temp dir rather than abort the whole target.
			result.Errors = append(result.Errors, scanner.ScanError{
				Path:      containerPathID(t),
				EnvType:   "container",
				Error:     fmt.Sprintf("container data-dir tmp base %q unusable; falling back to system temp: %v", dir, mkErr),
				Timestamp: time.Now().UTC(),
			})
		}
	}

	tmp, err := os.MkdirTemp(tmpBase, containerTempPrefix+"*")
	if err != nil {
		result.Errors = append(result.Errors, scanner.ScanError{
			Path:      containerPathID(t),
			EnvType:   "container",
			Error:     fmt.Sprintf("container tmp dir: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return
	}
	defer os.RemoveAll(tmp)

	// tctx (the per-container timeout) bounds the materialise copy loop
	// too, not just the sub-scan.  0 byte budget => Materialize uses its
	// default per-container ceiling.
	matErrs, err := Materialize(tctx, &t.MergedRootFS, tmp, 0)
	// Non-fatal per-file materialise errors (oversize skips, copy
	// failures) flow up annotated with the container ID so operators
	// can correlate a missing path back to the layer it lived in.
	for _, e := range matErrs {
		e.Path = containerPathID(t) + ":" + trimRootPrefix(e.Path, tmp)
		result.Errors = append(result.Errors, e)
	}
	if err != nil {
		result.Errors = append(result.Errors, scanner.ScanError{
			Path:      containerPathID(t),
			EnvType:   "container",
			Error:     fmt.Sprintf("materialise merged rootfs: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Sub-Runner: inherits MaxDepth + MaxWorkers from baseCfg,
	// scopes to the materialised tree as its ScanRoot.  Container
	// nesting is never recursive — ScanContainers is flipped off
	// on the sub-config explicitly.
	subCfg := baseCfg
	subCfg.ScanRoot = tmp
	subCfg.ScanContainers = false

	sub := scanner.NewRunner(subCfg)
	subRes, err := sub.Run(tctx)
	if err != nil {
		result.Errors = append(result.Errors, scanner.ScanError{
			Path:      containerPathID(t),
			EnvType:   "container",
			Error:     fmt.Sprintf("container sub-scan: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Decorate every package emitted by the sub-scan with the
	// container's origin metadata and merge.
	for _, p := range subRes.Packages {
		p.ContainerImageID = t.ImageID
		p.ContainerImageTags = t.ImageTags
		p.ContainerID = t.ContainerID
		p.ContainerName = t.ContainerName
		p.ContainerRuntime = string(t.Runtime)
		// Rewrite install paths so operators see
		// `/usr/lib/python3.12/...` inside a container rather
		// than the temp-dir leak.  The scanner emitted paths
		// relative to the materialised root; trim the temp prefix.
		p.InstallPath = trimRootPrefix(p.InstallPath, tmp)
		p.Environment = trimRootPrefix(p.Environment, tmp)
		result.Packages = append(result.Packages, p)
	}
	// Sub-scan errors flow up too; annotate with the container ID
	// so operators can correlate.
	for _, e := range subRes.Errors {
		e.Path = containerPathID(t) + ":" + trimRootPrefix(e.Path, tmp)
		result.Errors = append(result.Errors, e)
	}
}

// containerPathID returns a human-meaningful identifier for a
// ContainerTarget used in ScanError.Path.  Prefer the container ID
// when we have one, then fall back to "<runtime>:<image_id>" for
// image-only targets.
func containerPathID(t ContainerTarget) string {
	if t.ContainerID != "" {
		return string(t.Runtime) + ":" + t.ContainerID
	}
	return string(t.Runtime) + ":" + t.ImageID
}

// trimRootPrefix removes the materialised-root prefix from a path so
// downstream consumers see the in-container path.  If prefix doesn't
// match, returns the original.
func trimRootPrefix(path, root string) string {
	if path == "" || root == "" {
		return path
	}
	// Compare in forward-slash space.  The sub-Runner's paths are now
	// separator-normalised (Runner.Run → NormalizePaths), while `root` is a
	// raw host temp dir that still carries native separators — on Windows the
	// two would otherwise never prefix-match and the temp dir would leak into
	// the reported in-container path.  Folding both sides to `/` also yields
	// the desired in-container path shape (`/usr/bin`), since a container's
	// own filesystem is always `/`-rooted regardless of the extracting host.
	p := strings.ReplaceAll(path, `\`, "/")
	r := strings.ReplaceAll(root, `\`, "/")
	if len(p) >= len(r) && p[:len(r)] == r {
		trimmed := p[len(r):]
		if len(trimmed) > 0 && trimmed[0] == '/' {
			return trimmed
		}
		return "/" + trimmed
	}
	return path
}
