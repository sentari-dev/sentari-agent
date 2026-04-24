// Package output formats ScanResult values for CLI display.
//
// Four formatters live here: JSON (machine-readable, stable wire
// shape), CSV (spreadsheet-friendly, flat table), Summary (short
// human-readable for interactive use), and Explain (verbose human-
// readable with highlights for the zeitgeist findings — recent
// installs, AI-agent surfaces, container visibility).
//
// Per the 2026-04-24 roadmap decision (``OSS ⊆ Enterprise``),
// every formatter here is reachable from both cmd/sentari-agent/main.go
// (community build) and cmd/sentari-agent/main_enterprise.go
// (enterprise build).  Enterprise adds additional *modes* on top
// (upload, serve, cache-drain) but every output format the community
// build supports is also available in Enterprise one-shot-scan
// mode — no divergence.
package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Format names the output modes callers can request.  Kept as
// typed strings (not an enum) because they flow in from a CLI
// flag; validating at the switch in Write is sufficient.
const (
	FormatJSON    = "json"
	FormatCSV     = "csv"
	FormatPretty  = "pretty"  // summary-level human output
	FormatExplain = "explain" // verbose human output with zeitgeist highlights
)

// recentInstallCutoff is the age threshold below which a package
// counts as "recently installed" for the Explain formatter's
// highlight block.  Matches the Aikido-style 48h heuristic and
// the default max_days the install_age policy rule uses.
const recentInstallCutoff = 48 * time.Hour

// Write formats ``result`` into ``w`` in the named ``format``.
// An unknown format name returns a typed error rather than falling
// back silently — callers should surface this at the CLI level.
func Write(w io.Writer, result *scanner.ScanResult, format string) error {
	if result == nil {
		return fmt.Errorf("output: nil ScanResult")
	}
	switch format {
	case FormatJSON:
		return writeJSON(w, result)
	case FormatCSV:
		return writeCSV(w, result)
	case FormatPretty:
		return writeSummary(w, result)
	case FormatExplain:
		return writeExplain(w, result)
	default:
		return fmt.Errorf("output: unknown format %q (want %s|%s|%s|%s)",
			format, FormatJSON, FormatCSV, FormatPretty, FormatExplain)
	}
}

// writeJSON preserves the pre-v0.2 stable wire shape: indented JSON
// encoded to the writer.  No trailing newline — that's the Write
// caller's choice.
func writeJSON(w io.Writer, result *scanner.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	_, err = w.Write(data)
	return err
}

// writeCSV emits the existing per-package spreadsheet format.
// Moved from cmd/sentari-agent/main.go so both build tags share
// one implementation.  Column order is pinned — downstream
// scripts depend on it.
func writeCSV(w io.Writer, result *scanner.ScanResult) error {
	b := &bytes.Buffer{}
	cw := csv.NewWriter(b)
	if err := cw.Write([]string{
		"Name", "Version", "InstallPath", "EnvType", "InterpreterVersion",
		"InstallerUser", "InstallDate", "Environment",
	}); err != nil {
		return err
	}
	for _, pkg := range result.Packages {
		if err := cw.Write([]string{
			pkg.Name, pkg.Version, pkg.InstallPath, pkg.EnvType,
			pkg.InterpreterVersion, pkg.InstallerUser, pkg.InstallDate,
			pkg.Environment,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}

// writeSummary is the short human-readable format — what a
// developer running ``sentari --scan`` on their laptop sees by
// default.  Aimed at under 15 lines for a typical host so the
// output fits in a single terminal screen.
func writeSummary(w io.Writer, result *scanner.ScanResult) error {
	fmt.Fprintf(w, "Sentari scan — %s (%s/%s)\n", result.Hostname, result.OS, result.Arch)
	fmt.Fprintf(w, "  scanned at %s\n", result.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "  agent     %s\n\n", result.AgentVersion)

	fmt.Fprintf(w, "Packages: %d    Errors: %d\n", len(result.Packages), len(result.Errors))

	if byEnv := countByEnv(result.Packages); len(byEnv) > 0 {
		fmt.Fprintln(w, "\nBy ecosystem:")
		for _, k := range sortedKeys(byEnv) {
			fmt.Fprintf(w, "  %-15s %d\n", k, byEnv[k])
		}
	}
	if len(result.ContainerTargets) > 0 {
		fmt.Fprintf(w, "\nContainers: %d discovered\n", len(result.ContainerTargets))
	}
	return nil
}

// writeExplain is the verbose human-readable format for
// ``sentari --scan --explain``.  Adds zeitgeist highlights on top
// of the summary: recent installs (the Aikido 48h talking point
// answered detectively), AI-agent surfaces (shadow-AI inventory),
// and per-error detail so developers debugging a scan see what
// went wrong without reaching for ``--format=json``.
func writeExplain(w io.Writer, result *scanner.ScanResult) error {
	if err := writeSummary(w, result); err != nil {
		return err
	}

	// Recent installs — the detective-rule equivalent of Aikido's
	// install-age primitive, exposed at the CLI so developers can
	// see what landed on their laptop without needing the server.
	recent := filterRecentInstalls(result.Packages, recentInstallCutoff)
	if len(recent) > 0 {
		fmt.Fprintf(w, "\nRecent installs (< %s):\n", recentInstallCutoff)
		for _, p := range recent {
			// Limit to the first 20 in explain mode — beyond that
			// the user should use ``--format=json`` and grep.
			fmt.Fprintf(w, "  %-40s %s    [%s]\n",
				p.Name, p.Version, p.InstallDate)
		}
		if len(recent) > 20 {
			fmt.Fprintf(w, "  ... and %d more; use --format=json for the full list\n",
				len(recent)-20)
		}
	}

	// Shadow-AI surface — the records the aiagents plugin emitted.
	// Split out so a developer sees "3 AI extensions, 2 MCP servers
	// configured" without scrolling through the full package list.
	ai := filterByEnv(result.Packages, "ai_agent")
	if len(ai) > 0 {
		fmt.Fprintf(w, "\nAI-agent surface: %d artefacts\n", len(ai))
		for _, p := range ai {
			fmt.Fprintf(w, "  %-40s %s\n", p.Name, p.Version)
		}
	}

	// Errors — surface the non-fatal scan errors in-line so the
	// developer sees what the scanner couldn't read.  JSON format
	// is the right path for parsing them; here we just list.
	if len(result.Errors) > 0 {
		fmt.Fprintln(w, "\nScan errors:")
		for i, e := range result.Errors {
			if i >= 10 {
				fmt.Fprintf(w, "  ... and %d more\n", len(result.Errors)-i)
				break
			}
			fmt.Fprintf(w, "  [%s] %s: %s\n", e.EnvType, e.Path, e.Error)
		}
	}
	return nil
}

// countByEnv returns env_type → count for the given package slice.
// Case-folded so ``pip`` / ``PIP`` would collapse (shouldn't happen
// in practice but keeps the output clean).
func countByEnv(pkgs []scanner.PackageRecord) map[string]int {
	out := map[string]int{}
	for _, p := range pkgs {
		out[strings.ToLower(p.EnvType)]++
	}
	return out
}

// sortedKeys returns a stable-ordered slice of map keys.  Used so
// the summary renders the same across runs.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// filterByEnv returns all packages with env_type == env.
func filterByEnv(pkgs []scanner.PackageRecord, env string) []scanner.PackageRecord {
	var out []scanner.PackageRecord
	for _, p := range pkgs {
		if strings.EqualFold(p.EnvType, env) {
			out = append(out, p)
		}
	}
	return out
}

// filterRecentInstalls returns every package whose InstallDate is
// within ``within`` of now.  InstallDate is an RFC3339 string on
// the wire; unparseable values are silently skipped (not all
// plugins populate it).  The returned slice is capped at 100
// items — anything more is noise in a human output.
func filterRecentInstalls(pkgs []scanner.PackageRecord, within time.Duration) []scanner.PackageRecord {
	cutoff := time.Now().UTC().Add(-within)
	var out []scanner.PackageRecord
	for _, p := range pkgs {
		if p.InstallDate == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, p.InstallDate)
		if err != nil {
			continue
		}
		if t.After(cutoff) {
			out = append(out, p)
			if len(out) >= 100 {
				break
			}
		}
	}
	// Most-recent first for terminal display.
	sort.Slice(out, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, out[i].InstallDate)
		tj, _ := time.Parse(time.RFC3339, out[j].InstallDate)
		return ti.After(tj)
	})
	return out
}
