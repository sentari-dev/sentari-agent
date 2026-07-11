// Tests for the shared one-shot-scan orchestration (oneshot.go), the primary
// local-scan CLI path (`--scan`, no server round-trip).  oneshot.go carries no
// build tag and is linked into every binary, so this test is likewise untagged
// and runs under both the community and enterprise builds.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/output"
)

// TestResolveOneShotFormat exercises every precedence branch of the format
// resolver: explicit --format wins over everything, then --explain, then the
// context-aware default (json to a file, pretty to stdout).
func TestResolveOneShotFormat(t *testing.T) {
	cases := []struct {
		name string
		opts oneShotOptions
		want string
	}{
		{
			name: "explicit format beats explain and output path",
			opts: oneShotOptions{format: output.FormatCSV, explain: true, outputPath: "/tmp/out"},
			want: output.FormatCSV,
		},
		{
			name: "explain wins when no explicit format",
			opts: oneShotOptions{explain: true, outputPath: "/tmp/out"},
			want: output.FormatExplain,
		},
		{
			name: "file output defaults to json",
			opts: oneShotOptions{outputPath: "/tmp/out"},
			want: output.FormatJSON,
		},
		{
			name: "stdout defaults to pretty",
			opts: oneShotOptions{},
			want: output.FormatPretty,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveOneShotFormat(tc.opts); got != tc.want {
				t.Fatalf("resolveOneShotFormat(%+v) = %q, want %q", tc.opts, got, tc.want)
			}
		})
	}
}

// TestRunOneShotWritesJSONToFile drives runOneShot end-to-end against a temp
// scan root and a temp output file, asserting a zero exit code and that the
// resolved format (json, the file-output default) was actually written and is
// valid JSON.  This covers the primary `--scan --output <file>` CLI path.
func TestRunOneShotWritesJSONToFile(t *testing.T) {
	scanRoot := t.TempDir()
	// A trivial project tree so the scan has something to walk without needing
	// any real interpreter or package manager present.
	if err := os.WriteFile(filepath.Join(scanRoot, "requirements.txt"), []byte("requests==2.0.0\n"), 0o600); err != nil {
		t.Fatalf("seed scan root: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "scan.json")
	cfg := scanner.Config{ScanRoot: scanRoot, MaxDepth: 3, MaxWorkers: 2}

	code := runOneShot(context.Background(), cfg, oneShotOptions{outputPath: outPath})
	if code != 0 {
		t.Fatalf("runOneShot exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("output file is empty; runOneShot wrote nothing")
	}
	// The file-output default is JSON — assert the sink actually received JSON.
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("output is not valid JSON (format not resolved to json?): %v\n%s", err, string(data))
	}
	// The 0600 file-perm contract for scan payloads on shared hosts.
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("output file perm = %o, want 600", perm)
	}
}

// TestRunOneShotExplicitFormatToFile confirms an explicit --format overrides the
// json-to-file default all the way through runOneShot's write path: requesting
// CSV yields a file whose contents are NOT JSON.
func TestRunOneShotExplicitFormatToFile(t *testing.T) {
	scanRoot := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "scan.csv")
	cfg := scanner.Config{ScanRoot: scanRoot, MaxDepth: 2, MaxWorkers: 2}

	code := runOneShot(context.Background(), cfg, oneShotOptions{
		outputPath: outPath,
		format:     output.FormatCSV,
	})
	if code != 0 {
		t.Fatalf("runOneShot exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	// CSV output must not parse as a JSON object — proves the explicit format
	// beat the file-output json default through the full write path.
	var payload map[string]any
	if json.Unmarshal(data, &payload) == nil {
		t.Fatalf("expected CSV, got JSON-parseable output: %s", string(data))
	}
	if strings.TrimSpace(string(data)) == "" {
		t.Fatal("CSV output is empty")
	}
}
