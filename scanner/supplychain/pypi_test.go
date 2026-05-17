package supplychain

import (
	"path/filepath"
	"testing"
)

func TestDetectInPipCache_yankedMarker(t *testing.T) {
	site := t.TempDir()
	distInfo := filepath.Join(site, "requests-2.31.0.dist-info")
	mustMkdir(t, distInfo)
	mustWrite(t, filepath.Join(distInfo, "METADATA"), "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")
	mustWrite(t, filepath.Join(distInfo, "YANKED"), "security issue: CVE-2024-XXXX")

	signals, err := DetectInPipCache(site)
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
	signals, err := DetectInPipCache(site)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals, got %+v", signals)
	}
}

func TestPypiMetadataFields(t *testing.T) {
	content := []byte("Metadata-Version: 2.1\nName: numpy\nVersion: 1.26.0\nSummary: ...\n")
	name, version := pypiMetadataFields(content)
	if name != "numpy" || version != "1.26.0" {
		t.Errorf("got (%q, %q), want (numpy, 1.26.0)", name, version)
	}
}
