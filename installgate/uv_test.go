package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// makeUvMap reuses ``proxy_endpoints["pypi"]`` because uv consumes
// the PyPI ecosystem — there's no separate "uv" endpoint slot in
// the policy-map shape (and adding one would over-fit the schema
// to a single tool).
func makeUvMap(endpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"pypi": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"pypi": endpoint,
		},
	}
}

// uvHomeOverride redirects the user-home env vars so UvPath
// resolves into the test-owned temp dir.
func uvHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", dir)
		return filepath.Join(dir, "uv", "uv.toml")
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", dir)
	return filepath.Join(dir, ".config", "uv", "uv.toml")
}

// --- UvPath -----------------------------------------------------------

func TestUvPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := uvHomeOverride(t, dir)
	got := UvPath(UvScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestUvPath_XDGOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG_CONFIG_HOME not used on Windows")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got := UvPath(UvScopeUser)
	want := filepath.Join(dir, "uv", "uv.toml")
	if got != want {
		t.Errorf("XDG override: got %q, want %q", got, want)
	}
}

func TestUvPath_SystemScope(t *testing.T) {
	got := UvPath(UvScopeSystem)
	switch runtime.GOOS {
	case "windows":
		// Either env-var-derived or fallback — both end with the
		// same suffix.
		if !strings.HasSuffix(got, filepath.Join("uv", "uv.toml")) {
			t.Errorf("Windows system scope: unexpected path %q", got)
		}
	default:
		if got != "/etc/uv/uv.toml" {
			t.Errorf("POSIX system scope: got %q, want /etc/uv/uv.toml", got)
		}
	}
}

// --- WriteUv ----------------------------------------------------------

func TestWriteUv_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := uvHomeOverride(t, dir)

	res, err := WriteUv(makeUvMap("https://proxy.example.test/pypi/simple/"), UvScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteUv: %v", err)
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
		"[[index]]",
		`name = "sentari-proxy"`,
		`url = "https://proxy.example.test/pypi/simple/"`,
		"default = true",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("uv.toml missing %q\nfull body:\n%s", s, got)
		}
	}
}

// Operator-curated uv.toml MUST NOT be touched.  Auth tokens for
// private indexes commonly land here.
func TestWriteUv_OperatorCuratedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := uvHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := `[[index]]
name = "internal"
url = "https://artifactory.corp.local/api/pypi/pypi/simple/"
default = true

[[index]]
name = "internal-auth"
url = "https://x:SECRET-DO-NOT-TOUCH@artifactory.corp.local/api/pypi/pypi/simple/"
`
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteUv(makeUvMap("https://proxy.example.test/pypi/simple/"), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteUv: %v", err)
	}
	if !res.SkippedOperator {
		t.Error("SkippedOperator should be true on operator-curated uv.toml")
	}
	if res.Changed {
		t.Error("Changed should be false")
	}
	got, _ := os.ReadFile(path)
	if string(got) != operatorBody {
		t.Errorf("operator uv.toml altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

func TestWriteUv_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	uvHomeOverride(t, dir)

	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WriteUv(makeUvMap("https://proxy.example.test/pypi/simple/"), UvScopeUser, mark); err != nil {
		t.Fatal(err)
	}
	r2, err := WriteUv(makeUvMap("https://proxy.example.test/pypi/simple/"), UvScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
	mark.Version = 2
	r3, err := WriteUv(makeUvMap("https://proxy.example.test/pypi/simple/"), UvScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r3.Changed {
		t.Error("version bump should report Changed=true")
	}
}

func TestWriteUv_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := uvHomeOverride(t, dir)
	res, err := WriteUv(makeUvMap(""), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteUv: %v", err)
	}
	if res.Changed || res.Removed || res.SkippedOperator {
		t.Errorf("expected all-false result, got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file created despite empty endpoint: stat err=%v", err)
	}
}

func TestWriteUv_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := uvHomeOverride(t, dir)
	if _, err := WriteUv(makeUvMap("https://proxy.example.test/pypi/simple/"), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}
	res, err := WriteUv(makeUvMap(""), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteUv: %v", err)
	}
	if !res.Removed {
		t.Error("Removed should be true")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove")
	}
}

func TestWriteUv_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := uvHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte("[[index]]\nname=\"corp\"\nurl=\"https://corp/\"\n")
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := WriteUv(makeUvMap(""), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Removed {
		t.Errorf("operator uv.toml touched: %+v", res)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(operatorBody) {
		t.Errorf("operator uv.toml altered")
	}
}

// TOML is double-quote-sensitive; an embedded ``"`` in the
// endpoint URL would terminate the quoted string and produce
// invalid TOML.  validateEndpoint already refuses control chars +
// spaces, but ``"`` and ``\`` are a separate class — uv's
// renderer guards them explicitly.
func TestWriteUv_RejectsTOMLHostileChars(t *testing.T) {
	dir := t.TempDir()
	path := uvHomeOverride(t, dir)

	cases := []string{
		`https://proxy.example.test/pypi/"break"/simple/`,
		`https://proxy.example.test/pypi\path/simple/`,
	}
	for _, ep := range cases {
		_, err := WriteUv(makeUvMap(ep), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file created for hostile endpoint %q", ep)
			_ = os.Remove(path)
		}
	}
}

func TestWriteUv_RejectsControlCharsInEndpoint(t *testing.T) {
	dir := t.TempDir()
	uvHomeOverride(t, dir)
	_, err := WriteUv(makeUvMap("https://proxy.example.test/\nx"), UvScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err == nil {
		t.Error("expected error for control byte in endpoint")
	}
}

func TestWriteUv_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	uvHomeOverride(t, dir)
	if _, err := WriteUv(nil, UvScopeUser, MarkerFields{KeyID: "primary"}); err == nil {
		t.Error("expected error on nil map")
	}
}
