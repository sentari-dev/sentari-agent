package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// makeNpmMap returns a verified-shape map with one ``npm`` proxy
// endpoint and a populated pypi block (so the orchestrator's pip
// writer doesn't trip over a missing ecosystem entry when the
// integration tests later exercise both writers).
func makeNpmMap(npmEndpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"npm": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"npm": npmEndpoint,
		},
	}
}

// npmHomeOverride redirects USERPROFILE / HOME so NpmPath resolves
// inside a test-owned temp dir.  Mirrors the pip writer's
// ``userHomeOverride`` but for npm-specific path resolution.
func npmHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
	return filepath.Join(dir, ".npmrc")
}

// --- NpmPath ----------------------------------------------------------

func TestNpmPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := npmHomeOverride(t, dir)
	got := NpmPath(NpmScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestNpmPath_SystemScope(t *testing.T) {
	got := NpmPath(NpmScopeSystem)
	switch runtime.GOOS {
	case "windows":
		if got != "" {
			t.Errorf("Windows system scope should soft-no-op, got %q", got)
		}
	default:
		if got != "/etc/npmrc" {
			t.Errorf("POSIX system scope: got %q, want /etc/npmrc", got)
		}
	}
}

// --- WriteNpm ---------------------------------------------------------

func TestWriteNpm_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	res, err := WriteNpm(makeNpmMap("https://proxy.example.test/npm/"), NpmScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	if res.Path != path {
		t.Errorf("Path: got %q, want %q", res.Path, path)
	}
	if !res.Changed {
		t.Error("Changed should be true on fresh write")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	wantSubstrs := []string{
		"# Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z)",
		"registry=https://proxy.example.test/npm/",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf(".npmrc missing %q\nfull body:\n%s", s, got)
		}
	}
}

// Regression for the trailing-slash gotcha: npm appends paths
// directly to the registry URL, so a missing trailing slash
// breaks tarball lookups silently.  The renderer normalises.
func TestWriteNpm_NormalisesTrailingSlash(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	res, err := WriteNpm(makeNpmMap("https://proxy.example.test/npm"), NpmScopeUser, MarkerFields{Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("expected Changed=true")
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "registry=https://proxy.example.test/npm/\n") {
		t.Errorf(".npmrc did not normalise trailing slash:\n%s", body)
	}
}

func TestWriteNpm_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	res, err := WriteNpm(makeNpmMap(""), NpmScopeUser, MarkerFields{Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	if res.Changed || res.Removed {
		t.Errorf("expected (Changed=false, Removed=false), got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("config created despite empty endpoint: stat err=%v", err)
	}
}

// Regression for the operator-curated-survival contract: an
// existing .npmrc *without* the Sentari marker (operator-installed
// auth tokens, custom cache, scoped registry mappings) MUST NOT be
// touched when the policy ships an empty endpoint.  Same data-loss
// guard the pip writer applies; npm is even higher stakes because
// .npmrc commonly carries auth tokens.
func TestWriteNpm_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte("//npm.internal.corp/:_authToken=secret-do-not-touch\nregistry=https://npm.internal.corp/\n")
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteNpm(makeNpmMap(""), NpmScopeUser, MarkerFields{Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	if res.Removed || res.Changed {
		t.Errorf("operator-curated .npmrc touched: %+v", res)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(operatorBody) {
		t.Errorf("operator .npmrc altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

func TestWriteNpm_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# Managed by Sentari (...)\nregistry=https://proxy.example.test/npm/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteNpm(makeNpmMap(""), NpmScopeUser, MarkerFields{Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	if !res.Removed {
		t.Error("Removed should be true when stale Sentari .npmrc exists and policy has no endpoint")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove: stat err=%v", err)
	}
}

func TestWriteNpm_IdempotentSecondCall(t *testing.T) {
	dir := t.TempDir()
	npmHomeOverride(t, dir)

	mark := MarkerFields{Version: 1730901234, KeyID: "primary", Applied: fixedTime}
	r1, err := WriteNpm(makeNpmMap("https://proxy.example.test/npm/"), NpmScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Changed {
		t.Fatal("first call should report Changed=true")
	}
	r2, err := WriteNpm(makeNpmMap("https://proxy.example.test/npm/"), NpmScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("second identical call should report Changed=false")
	}
}

func TestWriteNpm_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	npmHomeOverride(t, dir)
	if _, err := WriteNpm(nil, NpmScopeUser, MarkerFields{}); err == nil {
		t.Error("expected error on nil map")
	}
}
