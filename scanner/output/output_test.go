package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// fixtureResult builds a ScanResult with a mix of records across
// ecosystems + a fresh install + an AI-agent record + an error,
// so every Explain highlight is exercised by the same fixture.
func fixtureResult() *scanner.ScanResult {
	now := time.Now().UTC()
	return &scanner.ScanResult{
		DeviceID:     "test-device",
		Hostname:     "fixture.local",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    now,
		AgentVersion: "0.1.0-test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: "pip"},
			{Name: "urllib3", Version: "1.26.5", EnvType: "pip"},
			{Name: "org.apache.commons:commons-lang3", Version: "3.12.0", EnvType: "jvm"},
			// Fresh install — inside recentInstallCutoff.
			{
				Name:        "freshly-installed",
				Version:     "0.0.1",
				EnvType:     "pip",
				InstallDate: now.Add(-6 * time.Hour).Format(time.RFC3339),
			},
			// Ancient — outside cutoff, shouldn't show in recent-installs.
			{
				Name:        "old-pkg",
				Version:     "1.0.0",
				EnvType:     "pip",
				InstallDate: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			},
			// AI-agent record — shadow-AI highlight.
			{Name: "mcp:filesystem", Version: "1.2.3", EnvType: "ai_agent"},
		},
		Errors: []scanner.ScanError{
			{Path: "/var/lib/dpkg/status.bad", EnvType: "system_deb", Error: "parse error: line 3"},
		},
	}
}

// TestWrite_UnknownFormat: an unrecognised format value surfaces
// as a typed error instead of silently falling back, so main.go
// can treat it as a flag-parse failure.
func TestWrite_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, fixtureResult(), "yaml")
	if err == nil {
		t.Fatalf("expected error on unknown format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention unknown format; got %q", err)
	}
}

// TestWrite_JSON_RoundTrip: JSON output is still parseable into
// ScanResult so downstream pipelines depending on the wire shape
// don't break when anything else in this package changes.
func TestWrite_JSON_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, fixtureResult(), FormatJSON); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var decoded scanner.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if decoded.Hostname != "fixture.local" {
		t.Errorf("hostname: got %q", decoded.Hostname)
	}
	if len(decoded.Packages) != 6 {
		t.Errorf("packages: got %d want 6", len(decoded.Packages))
	}
}

// TestWrite_CSV_HasHeaderAndRows: CSV output carries the pinned
// column order + one row per package.  Downstream scripts parse
// this; column order changes are a breaking change and need to
// be caught here.
func TestWrite_CSV_HasHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, fixtureResult(), FormatCSV); err != nil {
		t.Fatalf("Write: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 7 { // 1 header + 6 packages
		t.Fatalf("expected 7 CSV lines (header + 6 rows); got %d", len(lines))
	}
	header := lines[0]
	wantCols := []string{"Name", "Version", "InstallPath", "EnvType",
		"InterpreterVersion", "InstallerUser", "InstallDate", "Environment"}
	for _, col := range wantCols {
		if !strings.Contains(header, col) {
			t.Errorf("header missing column %q; got %q", col, header)
		}
	}
}

// TestWrite_Pretty_HasExpectedSections: summary output includes
// the hostname line, package/error counts, and a by-ecosystem
// breakdown.  Exact formatting isn't pinned (that'd make every
// cosmetic tweak a test failure), but the load-bearing facts are.
func TestWrite_Pretty_HasExpectedSections(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, fixtureResult(), FormatPretty); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s := buf.String()
	for _, frag := range []string{
		"fixture.local",
		"Packages: 6",
		"Errors: 1",
		"By ecosystem:",
		"pip",
		"jvm",
		"ai_agent",
	} {
		if !strings.Contains(s, frag) {
			t.Errorf("pretty output missing %q; got\n%s", frag, s)
		}
	}
}

// TestWrite_Explain_Highlights: explain format surfaces the
// recent-install block (the Aikido-style talking point the
// format is built around) + the AI-agent surface block.  Both
// are the zeitgeist answers a dev running sentari --scan
// --explain expects to see.
func TestWrite_Explain_Highlights(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, fixtureResult(), FormatExplain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s := buf.String()
	// Recent-installs block.
	if !strings.Contains(s, "Recent installs") {
		t.Errorf("explain output missing 'Recent installs' header; got\n%s", s)
	}
	if !strings.Contains(s, "freshly-installed") {
		t.Errorf("explain output missing the recently-installed package")
	}
	if strings.Contains(s, "old-pkg") {
		t.Errorf("explain output should not include ancient packages in recent-installs")
	}
	// AI-agent block.
	if !strings.Contains(s, "AI-agent surface") {
		t.Errorf("explain output missing AI-agent surface block")
	}
	if !strings.Contains(s, "mcp:filesystem") {
		t.Errorf("explain output missing the AI-agent record")
	}
	// Errors block.
	if !strings.Contains(s, "Scan errors") {
		t.Errorf("explain output missing scan-errors block")
	}
}

// TestWrite_Explain_NoHighlightsWhenClean: with zero recent
// installs + zero AI-agent records + zero errors, the explain
// format still prints the summary but doesn't emit empty
// highlight headers.  Operators shouldn't see "Recent installs:"
// followed by nothing.
func TestWrite_Explain_NoHighlightsWhenClean(t *testing.T) {
	clean := &scanner.ScanResult{
		Hostname:     "clean.local",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    time.Now().UTC(),
		AgentVersion: "0.1.0-test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: "pip"},
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, clean, FormatExplain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s := buf.String()
	if strings.Contains(s, "Recent installs") {
		t.Errorf("clean fixture should not produce Recent-installs block")
	}
	if strings.Contains(s, "AI-agent surface") {
		t.Errorf("clean fixture should not produce AI-agent block")
	}
	if strings.Contains(s, "Scan errors") {
		t.Errorf("clean fixture should not produce errors block")
	}
}

// TestResolveFormat_Defaults: verifies the default-pick logic
// matches the documented behaviour.
func TestFilterRecentInstalls_ParsesRFC3339(t *testing.T) {
	now := time.Now().UTC()
	pkgs := []scanner.PackageRecord{
		{Name: "fresh", InstallDate: now.Add(-1 * time.Hour).Format(time.RFC3339)},
		{Name: "old", InstallDate: now.Add(-365 * 24 * time.Hour).Format(time.RFC3339)},
		{Name: "bogus", InstallDate: "not-a-timestamp"},
		{Name: "no-date", InstallDate: ""},
	}
	got := filterRecentInstalls(pkgs, 48*time.Hour)
	if len(got) != 1 {
		t.Fatalf("expected 1 recent install; got %d: %+v", len(got), got)
	}
	if got[0].Name != "fresh" {
		t.Errorf("wrong package flagged: %s", got[0].Name)
	}
}

// TestWrite_NilResult: defensive — a nil result is a caller bug
// but shouldn't crash the formatter.
func TestWrite_NilResult(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, nil, FormatPretty)
	if err == nil {
		t.Errorf("expected error on nil result")
	}
}
