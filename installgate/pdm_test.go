package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func makePdmMap(endpoint string) *scanner.InstallGateMap {
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

func pdmHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LOCALAPPDATA", dir)
		return filepath.Join(dir, "pdm", "pdm", "config.toml")
	case "darwin":
		t.Setenv("HOME", dir)
		return filepath.Join(dir, "Library", "Application Support", "pdm", "config.toml")
	default:
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", dir)
		return filepath.Join(dir, ".config", "pdm", "config.toml")
	}
}

// --- PdmPath ----------------------------------------------------------

func TestPdmPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := pdmHomeOverride(t, dir)
	got := PdmPath(PdmScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestPdmPath_SystemScopeIsEmpty(t *testing.T) {
	// pdm has no system-wide config path.  PdmScopeSystem is
	// kept for symmetry with the other scope enums but always
	// returns empty (soft no-op upstream).
	if got := PdmPath(PdmScopeSystem); got != "" {
		t.Errorf("PdmScopeSystem should always return empty, got %q", got)
	}
}

func TestPdmPath_LinuxXDGOverride(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("XDG_CONFIG_HOME only used on Linux/freebsd in PdmPath")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got := PdmPath(PdmScopeUser)
	want := filepath.Join(dir, "pdm", "config.toml")
	if got != want {
		t.Errorf("XDG override: got %q, want %q", got, want)
	}
}

// --- WritePdm ---------------------------------------------------------

func TestWritePdm_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := pdmHomeOverride(t, dir)

	res, err := WritePdm(makePdmMap("https://proxy.example.test/pypi/simple/"), PdmScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WritePdm: %v", err)
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
		"[pypi]",
		`url = "https://proxy.example.test/pypi/simple/"`,
		"verify_ssl = true",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("pdm config.toml missing %q\nfull body:\n%s", s, got)
		}
	}
}

func TestWritePdm_OperatorCuratedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := pdmHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := `[pypi]
url = "https://artifactory.corp.local/api/pypi/pypi/simple/"
username = "build-bot"
password = "SECRET-DO-NOT-TOUCH"
`
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WritePdm(makePdmMap("https://proxy.example.test/pypi/simple/"), PdmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePdm: %v", err)
	}
	if !res.SkippedOperator {
		t.Error("SkippedOperator should be true on operator-curated pdm config")
	}
	got, _ := os.ReadFile(path)
	if string(got) != operatorBody {
		t.Errorf("operator pdm config altered")
	}
}

func TestWritePdm_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	pdmHomeOverride(t, dir)
	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WritePdm(makePdmMap("https://proxy.example.test/pypi/simple/"), PdmScopeUser, mark); err != nil {
		t.Fatal(err)
	}
	r2, err := WritePdm(makePdmMap("https://proxy.example.test/pypi/simple/"), PdmScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
}

func TestWritePdm_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := pdmHomeOverride(t, dir)
	res, err := WritePdm(makePdmMap(""), PdmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Removed || res.SkippedOperator {
		t.Errorf("expected all-false, got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file created despite empty endpoint")
	}
}

func TestWritePdm_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := pdmHomeOverride(t, dir)
	if _, err := WritePdm(makePdmMap("https://proxy.example.test/pypi/simple/"), PdmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}
	res, err := WritePdm(makePdmMap(""), PdmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Removed {
		t.Error("Removed should be true")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove")
	}
}

func TestWritePdm_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := pdmHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte("[pypi]\nurl=\"https://corp/\"\n")
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := WritePdm(makePdmMap(""), PdmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Removed {
		t.Errorf("operator pdm config touched: %+v", res)
	}
}

func TestWritePdm_RejectsTOMLHostileChars(t *testing.T) {
	dir := t.TempDir()
	pdmHomeOverride(t, dir)
	for _, ep := range []string{
		`https://proxy.example.test/"break"/`,
		`https://proxy.example.test/path\x/`,
	} {
		_, err := WritePdm(makePdmMap(ep), PdmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
	}
}

func TestWritePdm_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	pdmHomeOverride(t, dir)
	if _, err := WritePdm(nil, PdmScopeUser, MarkerFields{KeyID: "primary"}); err == nil {
		t.Error("expected error on nil map")
	}
}
