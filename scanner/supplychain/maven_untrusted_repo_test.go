package supplychain

import (
	"path/filepath"
	"testing"
)

const remoteRepoUntrusted = `#NOTE: This is a Maven Resolver internal implementation file
#Thu Jun 26 10:00:00 UTC 2026
evil-lib-1.0.0.jar>evil-repo=https://evil.example/maven
`

const remoteRepoCentralEmpty = `#NOTE: This is a Maven Resolver internal implementation file
#Thu Jun 26 10:00:00 UTC 2026
lib-a-1.0.0.jar>central=
`

const remoteRepoCentralURL = `#NOTE: This is a Maven Resolver internal implementation file
#Thu Jun 26 10:00:00 UTC 2026
lib-a-1.0.0.jar>central=https://repo1.maven.org/maven2
`

// TestUntrustedRepo_emitsSignal verifies that a _remote.repositories file
// referencing a non-Maven-Central repo emits a maven_untrusted_repo signal
// with the correct coordinates derived from the directory path.
func TestUntrustedRepo_emitsSignal(t *testing.T) {
	m2 := t.TempDir()
	versionDir := filepath.Join(m2, "com", "example", "evil-lib", "1.0.0")
	mustMkdir(t, versionDir)
	mustWrite(t, filepath.Join(versionDir, "_remote.repositories"), remoteRepoUntrusted)

	signals, err := DetectUntrustedRepos(m2)
	if err != nil {
		t.Fatalf("DetectUntrustedRepos failed: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(signals), signals)
	}
	s := signals[0]
	if s.SignalType != "maven_untrusted_repo" {
		t.Errorf("wrong signal_type: %q", s.SignalType)
	}
	if s.Severity != "high" {
		t.Errorf("wrong severity: %q", s.Severity)
	}
	if s.Source != "agent-maven-repo" {
		t.Errorf("wrong source: %q", s.Source)
	}
	if s.PackageName != "com.example:evil-lib" {
		t.Errorf("wrong package_name: %q", s.PackageName)
	}
	if s.PackageVersion != "1.0.0" {
		t.Errorf("wrong package_version: %q", s.PackageVersion)
	}
	if s.Ecosystem != "maven" {
		t.Errorf("wrong ecosystem: %q", s.Ecosystem)
	}
}

// TestUntrustedRepo_centralTrusted verifies that a _remote.repositories
// file referencing "central" with an empty URL produces no signal.
func TestUntrustedRepo_centralTrusted(t *testing.T) {
	m2 := t.TempDir()
	versionDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, versionDir)
	mustWrite(t, filepath.Join(versionDir, "_remote.repositories"), remoteRepoCentralEmpty)

	signals, err := DetectUntrustedRepos(m2)
	if err != nil {
		t.Fatalf("DetectUntrustedRepos failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals for central (empty URL), got %+v", signals)
	}
}

// TestUntrustedRepo_centralUrlTrusted verifies that a _remote.repositories
// file using the canonical Maven Central URL is treated as trusted.
func TestUntrustedRepo_centralUrlTrusted(t *testing.T) {
	m2 := t.TempDir()
	versionDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, versionDir)
	mustWrite(t, filepath.Join(versionDir, "_remote.repositories"), remoteRepoCentralURL)

	signals, err := DetectUntrustedRepos(m2)
	if err != nil {
		t.Fatalf("DetectUntrustedRepos failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals for canonical Central URL, got %+v", signals)
	}
}
