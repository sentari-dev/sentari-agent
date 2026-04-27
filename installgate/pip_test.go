package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// makeMap returns a minimal verified-shape InstallGateMap with one
// pypi proxy endpoint and one no-op (empty) endpoint for npm.  The
// rest of the ecosystems map to the same empty-block shape the
// production envelope builder produces.
func makeMap(pypiEndpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"pypi": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"pypi": pypiEndpoint,
		},
	}
}

// userHomeOverride redirects HOME (or APPDATA on Windows) at the
// PipPath helper so tests don't have to special-case the running
// user's actual home dir.  Returns the path PipPath will then
// resolve to.
func userHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", dir)
		return filepath.Join(dir, "pip", "pip.ini")
	default:
		// Clear XDG_CONFIG_HOME so the home-fallback path is
		// exercised — that's the path that production agents on
		// fresh laptops will hit.
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", dir)
		return filepath.Join(dir, ".config", "pip", "pip.conf")
	}
}

// --- PipPath ----------------------------------------------------------

func TestPipPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := userHomeOverride(t, dir)
	got := PipPath(PipScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestPipPath_XDGOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG_CONFIG_HOME not used on Windows")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got := PipPath(PipScopeUser)
	want := filepath.Join(dir, "pip", "pip.conf")
	if got != want {
		t.Errorf("XDG override: got %q, want %q", got, want)
	}
}

// --- WritePip ---------------------------------------------------------

func TestWritePip_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	res, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if res.Path != path {
		t.Errorf("Path: got %q, want %q", res.Path, path)
	}
	if !res.Changed {
		t.Error("Changed should be true on fresh write")
	}
	if res.Removed {
		t.Error("Removed should be false on fresh write")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	wantSubstrs := []string{
		"# Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z)",
		"[global]",
		"index-url = https://proxy.example.test/pypi/simple/",
		"trusted-host = proxy.example.test",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("rendered config missing %q\nfull body:\n%s", s, got)
		}
	}
}

func TestWritePip_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	// Empty endpoint → fail-open: no file written, nothing changed,
	// nothing removed (because nothing existed).
	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if res.Changed || res.Removed {
		t.Errorf("expected (Changed=false, Removed=false), got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("config was created despite empty endpoint: stat err=%v", err)
	}
}

func TestWritePip_NoProxyExistingConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	// Pre-existing Sentari-managed config from a previous run.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# Managed by Sentari (...)\n[global]\nindex-url=foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Policy now ships no proxy URL.  Fail-open semantic: remove
	// the file so pip falls back to upstream.
	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if !res.Removed {
		t.Error("Removed should be true when stale config existed and policy has no endpoint")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove: stat err=%v", err)
	}
}

// Regression test for the data-loss bug Copilot caught on the
// initial PR: an operator-curated pip.conf (no Sentari marker)
// must NEVER be removed by the fail-open path, even when the
// policy-map drops the proxy URL.  Operator configs that pre-date
// install-gate enrolment are off-limits to the writer.
func TestWritePip_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte("[global]\nindex-url = https://artifactory.corp.local/api/pypi/pypi/simple/\n")
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}

	// Empty endpoint should NOT touch this file.
	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if res.Removed || res.Changed {
		t.Errorf("operator-curated config touched: %+v", res)
	}

	// File still present, byte-identical.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(operatorBody) {
		t.Errorf("operator config altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

func TestWritePip_IdempotentSecondCall(t *testing.T) {
	dir := t.TempDir()
	userHomeOverride(t, dir)

	mark := MarkerFields{Version: 1730901234, KeyID: "primary", Applied: fixedTime}
	r1, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Changed {
		t.Fatal("first call should report Changed=true")
	}
	r2, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("second identical call should report Changed=false")
	}
}

func TestWritePip_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	userHomeOverride(t, dir)
	if _, err := WritePip(nil, PipScopeUser, MarkerFields{}); err == nil {
		t.Error("expected error on nil map")
	}
}

// Endpoint-injection guard parallel to the npm test: a CR / LF in
// the proxy URL would let a tampered policy-map smuggle a second
// ``index-url =`` line into pip.conf and silently swap out the
// proxy.  validateEndpoint refuses control bytes before the
// renderer touches the file.
func TestWritePip_RejectsControlCharsInEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	cases := []string{
		// Mid-string LF — would smuggle a second index-url line.
		"https://proxy.example.test/pypi/simple/\nindex-url = https://evil/simple/",
		// Mid-string CR.
		"https://proxy.example.test/pypi/\rsimple/",
		// Embedded space — pip silently truncates and ends up
		// applying a half-URL.
		"https://proxy.example.test/pypi /simple/",
	}
	for _, ep := range cases {
		_, err := WritePip(makeMap(ep), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file created for invalid endpoint %q: stat err=%v", ep, err)
			_ = os.Remove(path)
		}
	}
}

// --- hostOf -----------------------------------------------------------

func TestHostOf_Variants(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{in: "https://proxy.example.test/pypi/simple/", want: "proxy.example.test"},
		{in: "http://proxy.example.test/pypi/", want: "proxy.example.test"},
		{in: "https://proxy.example.test:8443/pypi/", want: "proxy.example.test"},
		{in: "https://proxy.example.test", want: "proxy.example.test"},
		// IPv6 — keeps brackets, drops :port suffix.
		{in: "https://[::1]:8443/pypi/", want: "[::1]"},
		// Bare host with no scheme is acceptable too — operators
		// might paste a hostname without scheme into config.
		{in: "proxy.example.test/pypi/", want: "proxy.example.test"},
		{in: "", err: true},
	}
	for _, c := range cases {
		got, err := hostOf(c.in)
		if c.err {
			if err == nil {
				t.Errorf("hostOf(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("hostOf(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("hostOf(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}
