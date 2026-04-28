package installgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func makeGradleMap(endpoint string) *scanner.InstallGateMap {
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

// gradleHomeOverride redirects HOME / USERPROFILE so GradlePath
// resolves into the test-owned temp dir.
func gradleHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv("GRADLE_USER_HOME", "")
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	return filepath.Join(dir, ".gradle", "init.d", "sentari-proxy.gradle")
}

// --- GradlePath -------------------------------------------------------

func TestGradlePath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := gradleHomeOverride(t, dir)
	got := GradlePath(GradleScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestGradlePath_GradleUserHomeOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRADLE_USER_HOME", dir)
	got := GradlePath(GradleScopeUser)
	want := filepath.Join(dir, "init.d", "sentari-proxy.gradle")
	if got != want {
		t.Errorf("GRADLE_USER_HOME override: got %q, want %q", got, want)
	}
}

func TestGradlePath_SystemScopeNeedsGradleHome(t *testing.T) {
	t.Setenv("GRADLE_HOME", "")
	if got := GradlePath(GradleScopeSystem); got != "" {
		t.Errorf("system scope without GRADLE_HOME: got %q, want empty", got)
	}
	dir := t.TempDir()
	t.Setenv("GRADLE_HOME", dir)
	got := GradlePath(GradleScopeSystem)
	want := filepath.Join(dir, "init.d", "sentari-proxy.gradle")
	if got != want {
		t.Errorf("system scope: got %q, want %q", got, want)
	}
}

// --- WriteGradle ------------------------------------------------------

func TestWriteGradle_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := gradleHomeOverride(t, dir)

	res, err := WriteGradle(makeGradleMap("https://proxy.example.test/maven/"), GradleScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteGradle: %v", err)
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
		"// Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z)",
		"allprojects",
		"repositories",
		"maven",
		"url 'https://proxy.example.test/maven/'",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("init script missing %q\nfull body:\n%s", s, got)
		}
	}
}

func TestWriteGradle_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	gradleHomeOverride(t, dir)
	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WriteGradle(makeGradleMap("https://proxy.example.test/maven/"), GradleScopeUser, mark); err != nil {
		t.Fatal(err)
	}
	r2, err := WriteGradle(makeGradleMap("https://proxy.example.test/maven/"), GradleScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
	mark.Version = 2
	r3, err := WriteGradle(makeGradleMap("https://proxy.example.test/maven/"), GradleScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r3.Changed {
		t.Error("version bump should report Changed=true")
	}
}

func TestWriteGradle_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := gradleHomeOverride(t, dir)
	res, err := WriteGradle(makeGradleMap(""), GradleScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Removed {
		t.Errorf("expected all-false, got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file created despite empty endpoint")
	}
}

func TestWriteGradle_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := gradleHomeOverride(t, dir)
	if _, err := WriteGradle(makeGradleMap("https://proxy.example.test/maven/"), GradleScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}
	res, err := WriteGradle(makeGradleMap(""), GradleScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Removed {
		t.Error("Removed should be true when stale Sentari init script + no endpoint")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove")
	}
}

// Operator-curated init scripts in the same init.d directory MUST
// be preserved.  Our writer owns ``sentari-proxy.gradle`` only;
// other ``.gradle`` files in init.d are operator territory.
func TestWriteGradle_LeavesOtherInitScriptsAlone(t *testing.T) {
	dir := t.TempDir()
	path := gradleHomeOverride(t, dir)
	initD := filepath.Dir(path)
	if err := os.MkdirAll(initD, 0o755); err != nil {
		t.Fatal(err)
	}
	otherScript := filepath.Join(initD, "99-corp.gradle")
	if err := os.WriteFile(otherScript, []byte("// operator-curated\nallprojects { /* ... */ }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteGradle(makeGradleMap("https://proxy.example.test/maven/"), GradleScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(otherScript); err != nil {
		t.Errorf("operator init script disappeared: %v", err)
	}
}

func TestWriteGradle_RejectsGroovyHostileChars(t *testing.T) {
	dir := t.TempDir()
	gradleHomeOverride(t, dir)
	for _, ep := range []string{
		`https://proxy.example.test/maven/'); evil_code()/`,
		`https://proxy.example.test/path\x/`,
	} {
		_, err := WriteGradle(makeGradleMap(ep), GradleScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
	}
}

func TestWriteGradle_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	gradleHomeOverride(t, dir)
	if _, err := WriteGradle(nil, GradleScopeUser, MarkerFields{KeyID: "primary"}); err == nil {
		t.Error("expected error on nil map")
	}
}

// --- isSentariManaged for slash-marker --------------------------------

func TestIsSentariManaged_SlashMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentari-proxy.gradle")
	body := `// Managed by Sentari (version=1, signed=primary, applied=2026-04-25T10:00:00Z)
allprojects { repositories { } }
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed, err := isSentariManaged(path)
	if err != nil {
		t.Fatal(err)
	}
	if !managed {
		t.Error("slash-marker file not recognised as Sentari-managed")
	}
}
