package installgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func makeYarnBerryMap(endpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"npm": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"npm": endpoint,
		},
	}
}

func yarnBerryHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	return filepath.Join(dir, ".yarnrc.yml")
}

// --- YarnBerryPath ----------------------------------------------------

func TestYarnBerryPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := yarnBerryHomeOverride(t, dir)
	got := YarnBerryPath(YarnBerryScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestYarnBerryPath_SystemScopeIsEmpty(t *testing.T) {
	if got := YarnBerryPath(YarnBerryScopeSystem); got != "" {
		t.Errorf("system scope should be empty (soft no-op), got %q", got)
	}
}

// --- WriteYarnBerry ---------------------------------------------------

func TestWriteYarnBerry_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := yarnBerryHomeOverride(t, dir)

	res, err := WriteYarnBerry(makeYarnBerryMap("https://proxy.example.test/npm/"), YarnBerryScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteYarnBerry: %v", err)
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
		`npmRegistryServer: "https://proxy.example.test/npm/"`,
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf(".yarnrc.yml missing %q\nfull body:\n%s", s, got)
		}
	}
}

// Trailing-slash normalisation regression — yarn berry follows
// the npm convention that a missing trailing slash silently
// breaks tarball lookups.
func TestWriteYarnBerry_NormalisesTrailingSlash(t *testing.T) {
	dir := t.TempDir()
	path := yarnBerryHomeOverride(t, dir)
	res, err := WriteYarnBerry(makeYarnBerryMap("https://proxy.example.test/npm"), YarnBerryScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("expected Changed=true")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `npmRegistryServer: "https://proxy.example.test/npm/"`) {
		t.Errorf(".yarnrc.yml did not normalise trailing slash:\n%s", body)
	}
}

func TestWriteYarnBerry_OperatorCuratedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := yarnBerryHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := `npmRegistryServer: "https://npm.internal.corp/"
npmAuthToken: "SECRET-DO-NOT-TOUCH"
`
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := WriteYarnBerry(makeYarnBerryMap("https://proxy.example.test/npm/"), YarnBerryScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SkippedOperator {
		t.Error("SkippedOperator should be true on operator-curated .yarnrc.yml")
	}
	got, _ := os.ReadFile(path)
	if string(got) != operatorBody {
		t.Errorf("operator .yarnrc.yml altered")
	}
}

func TestWriteYarnBerry_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	yarnBerryHomeOverride(t, dir)
	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WriteYarnBerry(makeYarnBerryMap("https://proxy.example.test/npm/"), YarnBerryScopeUser, mark); err != nil {
		t.Fatal(err)
	}
	r2, err := WriteYarnBerry(makeYarnBerryMap("https://proxy.example.test/npm/"), YarnBerryScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
}

func TestWriteYarnBerry_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := yarnBerryHomeOverride(t, dir)
	res, err := WriteYarnBerry(makeYarnBerryMap(""), YarnBerryScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
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

func TestWriteYarnBerry_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := yarnBerryHomeOverride(t, dir)
	if _, err := WriteYarnBerry(makeYarnBerryMap("https://proxy.example.test/npm/"), YarnBerryScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}
	res, err := WriteYarnBerry(makeYarnBerryMap(""), YarnBerryScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
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

func TestWriteYarnBerry_RejectsYAMLHostileChars(t *testing.T) {
	dir := t.TempDir()
	yarnBerryHomeOverride(t, dir)
	for _, ep := range []string{
		`https://proxy.example.test/npm/"break"/`,
		`https://proxy.example.test/path\x/`,
	} {
		_, err := WriteYarnBerry(makeYarnBerryMap(ep), YarnBerryScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
	}
}

func TestWriteYarnBerry_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	yarnBerryHomeOverride(t, dir)
	if _, err := WriteYarnBerry(nil, YarnBerryScopeUser, MarkerFields{KeyID: "primary"}); err == nil {
		t.Error("expected error on nil map")
	}
}
