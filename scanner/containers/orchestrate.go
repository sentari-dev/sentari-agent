package containers

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Default caps from the Sprint-17 plan §6 Phase C task 8.
const (
	defaultMaxContainersPerCycle = 100
	defaultPerContainerTimeout   = 60 * time.Second
)

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
//     resulting records back into ``result`` after decorating
//     them with ContainerImageID / ContainerID / etc.
//  4. Each target's sub-scan runs under a per-container context
//     deadline so a single bad image can't stall the whole phase.
//  5. Panic recovery per target — matches the Sprint-15 pattern
//     already used in Runner.scanEnvironment.
//
// When ctx is cancelled the loop exits early; partial results
// already merged into ``result`` are preserved.  ScanErrors are
// appended (never fatal) — the host scan is already done.
//
// Caller is responsible for setting baseCfg.ScanContainers; this
// function honours it but does not enforce feature-flag semantics.
func ScanAndAppend(ctx context.Context, baseCfg scanner.Config, result *scanner.ScanResult) {
	if result == nil {
		return
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

// scanOneTarget runs the sub-scan for a single ContainerTarget,
// safely appending its results to the parent ``result``.  Wrapped
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

	tmp, err := os.MkdirTemp("", "sentari-container-*")
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

	if err := Materialize(&t.MergedRootFS, tmp); err != nil {
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
		// ``/usr/lib/python3.12/...`` inside a container rather
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
	if len(path) >= len(root) && path[:len(root)] == root {
		trimmed := path[len(root):]
		if len(trimmed) > 0 && trimmed[0] == '/' {
			return trimmed
		}
		return "/" + trimmed
	}
	return path
}
