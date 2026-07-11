package supplychain

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDetectInPipCache_yankedMarker(t *testing.T) {
	site := t.TempDir()
	distInfo := filepath.Join(site, "requests-2.31.0.dist-info")
	mustMkdir(t, distInfo)
	mustWrite(t, filepath.Join(distInfo, "METADATA"), "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")
	mustWrite(t, filepath.Join(distInfo, "YANKED"), "security issue: CVE-2024-XXXX")

	signals, err := DetectInPipCache(context.Background(), site)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 1 || signals[0].SignalType != "yanked" || signals[0].PackageName != "requests" {
		t.Fatalf("expected 1 yanked signal for requests, got %+v", signals)
	}
	if reason, ok := signals[0].Raw["reason"].(string); !ok || reason == "" {
		t.Errorf("expected reason to be carried in Raw, got %+v", signals[0].Raw)
	}
}

func TestDetectInPipCache_noYankedMarkerYieldsNothing(t *testing.T) {
	site := t.TempDir()
	distInfo := filepath.Join(site, "boring-1.0.0.dist-info")
	mustMkdir(t, distInfo)
	mustWrite(t, filepath.Join(distInfo, "METADATA"), "Metadata-Version: 2.1\nName: boring\nVersion: 1.0.0\n")
	signals, err := DetectInPipCache(context.Background(), site)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals, got %+v", signals)
	}
}

// TestPypiMetadataFields_malformed feeds garbage, truncated, control-byte,
// and key-less METADATA to the field parser and asserts it never panics and
// never fabricates a coordinate from bytes that carry no Name/Version. A
// dist-info METADATA is attacker-influenceable, so a crash or a bogus
// coordinate corrupts the supply-chain report.
func TestPypiMetadataFields_malformed(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t\n"},
		{"no fields", "Summary: nothing useful here\n"},
		{"garbage tokens", ":::\n@@@\n- - -\n"},
		{"control bytes", "\x00\x01\x02Name:\x00\n"},
		{"name key no value", "Name:\nVersion:\n"},
		{"lowercase keys ignored", "name: foo\nversion: 1.0.0\n"},
		{"prefix-only not a field", "Name-Extra: foo\nVersioning: 1.0.0\n"},
		{"no newline", "Metadata-Version: 2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, version := pypiMetadataFields([]byte(tc.content))
			if name != "" {
				t.Errorf("expected empty name for %q, got name=%q version=%q", tc.name, name, version)
			}
		})
	}
}

// TestDetectInPipCache_malformedMetadata drives the full walk with an
// unparsable METADATA (even alongside a YANKED marker) and asserts no panic
// and no signal: a manifest with no Name must not yield a coordinate-less
// yanked signal.
func TestDetectInPipCache_malformedMetadata(t *testing.T) {
	cases := []string{
		"",
		"   \n\t\n",
		"garbage without keys\n",
		"\x00\x01\x02Name:\x00\n",
		"Summary: no name or version\n",
	}
	for i, content := range cases {
		content := content
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			site := t.TempDir()
			distInfo := filepath.Join(site, "broken-0.0.0.dist-info")
			mustMkdir(t, distInfo)
			mustWrite(t, filepath.Join(distInfo, "METADATA"), content)
			// A YANKED marker is present, so the ONLY thing suppressing a
			// signal is the parser correctly refusing to emit a nameless one.
			mustWrite(t, filepath.Join(distInfo, "YANKED"), "reason")
			signals, err := DetectInPipCache(context.Background(), site)
			if err != nil {
				t.Fatalf("detect returned error on malformed metadata: %v", err)
			}
			if len(signals) != 0 {
				t.Errorf("expected no signals for malformed metadata %q, got %+v", content, signals)
			}
		})
	}
}

func TestPypiMetadataFields(t *testing.T) {
	content := []byte("Metadata-Version: 2.1\nName: numpy\nVersion: 1.26.0\nSummary: ...\n")
	name, version := pypiMetadataFields(content)
	if name != "numpy" || version != "1.26.0" {
		t.Errorf("got (%q, %q), want (numpy, 1.26.0)", name, version)
	}
}
