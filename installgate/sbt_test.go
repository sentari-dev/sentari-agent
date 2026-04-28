package installgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func makeSbtMap(endpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"maven": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"maven": endpoint,
		},
	}
}

func sbtHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	return filepath.Join(dir, ".sbt", "repositories")
}

// --- SbtPath ----------------------------------------------------------

func TestSbtPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := sbtHomeOverride(t, dir)
	got := SbtPath(SbtScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestSbtPath_SystemScopeNeedsSbtHome(t *testing.T) {
	t.Setenv("SBT_HOME", "")
	if got := SbtPath(SbtScopeSystem); got != "" {
		t.Errorf("system scope without SBT_HOME: got %q, want empty", got)
	}
	dir := t.TempDir()
	t.Setenv("SBT_HOME", dir)
	got := SbtPath(SbtScopeSystem)
	want := filepath.Join(dir, "conf", "repositories")
	if got != want {
		t.Errorf("system scope: got %q, want %q", got, want)
	}
}

// --- WriteSbt ---------------------------------------------------------

func TestWriteSbt_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := sbtHomeOverride(t, dir)

	res, err := WriteSbt(makeSbtMap("https://proxy.example.test/maven/"), SbtScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteSbt: %v", err)
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
		"[repositories]",
		"sentari-proxy: https://proxy.example.test/maven/",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("repositories file missing %q\nfull body:\n%s", s, got)
		}
	}
}

func TestWriteSbt_OperatorCuratedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := sbtHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := `[repositories]
internal-corp: https://artifactory.corp.local/maven/, [organization]/[module]/[revision]/[type]s/[artifact](-[classifier]).[ext]
`
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := WriteSbt(makeSbtMap("https://proxy.example.test/maven/"), SbtScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SkippedOperator {
		t.Error("SkippedOperator should be true on operator-curated repositories file")
	}
	got, _ := os.ReadFile(path)
	if string(got) != operatorBody {
		t.Errorf("operator repositories file altered")
	}
}

func TestWriteSbt_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	sbtHomeOverride(t, dir)
	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WriteSbt(makeSbtMap("https://proxy.example.test/maven/"), SbtScopeUser, mark); err != nil {
		t.Fatal(err)
	}
	r2, err := WriteSbt(makeSbtMap("https://proxy.example.test/maven/"), SbtScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
}

func TestWriteSbt_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := sbtHomeOverride(t, dir)
	res, err := WriteSbt(makeSbtMap(""), SbtScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
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

func TestWriteSbt_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := sbtHomeOverride(t, dir)
	if _, err := WriteSbt(makeSbtMap("https://proxy.example.test/maven/"), SbtScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}
	res, err := WriteSbt(makeSbtMap(""), SbtScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
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

func TestWriteSbt_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := sbtHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte("[repositories]\ncorp: https://artifactory.corp.local/maven/\n")
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := WriteSbt(makeSbtMap(""), SbtScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Removed {
		t.Errorf("operator file touched: %+v", res)
	}
}

func TestWriteSbt_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	sbtHomeOverride(t, dir)
	if _, err := WriteSbt(nil, SbtScopeUser, MarkerFields{KeyID: "primary"}); err == nil {
		t.Error("expected error on nil map")
	}
}
