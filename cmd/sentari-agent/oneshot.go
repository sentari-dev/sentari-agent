// Shared one-shot-scan orchestration used by both the community
// (`!enterprise`) and enterprise builds.  Per the 2026-04-24 roadmap
// decision (OSS ⊆ Enterprise), every output format available in the
// community build is also available in the enterprise build when the
// operator invokes ``--scan`` for a local inventory without an upload
// round-trip.  Extracting the logic here prevents the two mains from
// drifting as new formatters are added.
//
// This file has no build tag and is linked into every binary.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/containers"
	"github.com/sentari-dev/sentari-agent/scanner/output"
)

// oneShotOptions carries the flag values a caller resolved from the
// CLI.  All fields optional: resolveFormat below settles defaults.
type oneShotOptions struct {
	outputPath  string // "" = stdout
	format      string // "" = auto-pick (pretty on stdout, json to file)
	explain     bool   // shorthand for format="explain"
}

// runOneShot executes a single scan using the supplied scanner
// Config, formats the result per opts, and writes to the chosen
// sink.  Returns 0 on success or a non-zero exit code the caller
// should pass straight to os.Exit.
//
// The scan config is the caller's responsibility — it encodes the
// scan root, depth, worker count, and container-scan opt-in.
func runOneShot(ctx context.Context, cfg scanner.Config, opts oneShotOptions) int {
	s := scanner.NewScanner(cfg)
	result, err := s.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		return 1
	}

	// Container-image scan phase.  Opt-in via cfg.ScanContainers;
	// when on, appends every runtime's targets + per-container
	// sub-scans into the same result.
	if cfg.ScanContainers {
		containers.ScanAndAppend(ctx, cfg, result)
	}

	format := resolveOneShotFormat(opts)

	if opts.outputPath != "" {
		// File output: 0600 so scan payloads don't leak through
		// permissive file perms on shared hosts.
		f, err := os.OpenFile(opts.outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open output file: %v\n", err)
			return 1
		}
		defer f.Close()
		if err := output.Write(f, result, format); err != nil {
			fmt.Fprintf(os.Stderr, "Formatting error: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr,
			"Results written to %s (%d packages found)\n",
			opts.outputPath, len(result.Packages))
		return 0
	}

	// Stdout output.
	if err := output.Write(os.Stdout, result, format); err != nil {
		fmt.Fprintf(os.Stderr, "Formatting error: %v\n", err)
		return 1
	}
	// JSON/CSV don't emit a trailing newline; add one so the
	// shell prompt doesn't collide with the scan payload on
	// interactive use.
	if format == output.FormatJSON || format == output.FormatCSV {
		fmt.Fprintln(os.Stdout)
	}
	return 0
}

// resolveOneShotFormat picks the effective format from the CLI
// options.  Precedence: explicit --format wins, then --explain,
// then context-aware default (pretty on stdout, json to file).
func resolveOneShotFormat(opts oneShotOptions) string {
	if opts.format != "" {
		return opts.format
	}
	if opts.explain {
		return output.FormatExplain
	}
	if opts.outputPath != "" {
		return output.FormatJSON
	}
	return output.FormatPretty
}

