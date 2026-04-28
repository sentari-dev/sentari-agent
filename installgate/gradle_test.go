package installgate

import (
	"fmt"
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
		"def sentariProxyUrl = 'https://proxy.example.test/maven/'",
		// Plugin resolution surface — must clear before adding so
		// the Gradle Plugin Portal default doesn't survive.
		"beforeSettings { settings ->",
		"settings.pluginManagement.repositories.clear()",
		"settings.pluginManagement.repositories.maven { url sentariProxyUrl }",
		"allprojects {",
		// Buildscript classpath — cleared per-project.
		"buildscript {",
		"repositories.clear()",
		"repositories.maven { url sentariProxyUrl }",
		// Dependency resolution — afterEvaluate runs AFTER any
		// project-level repositories { ... } block.
		"afterEvaluate {",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("init script missing %q\nfull body:\n%s", s, got)
		}
	}
	// Negative assertion: the rendered script must NOT contain
	// an "add-only" repositories block (no clear()), which would
	// silently append rather than replace.
	if strings.Contains(got, "repositories {\n            maven {") &&
		!strings.Contains(got, "repositories.clear()") {
		t.Errorf("init script appears to use append-only repositories block (Copilot finding regression):\n%s", got)
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

// --- validateRenderedGradle (render-time structural canary) -----------

// Happy path: the actual renderer's output passes the canary.
// If this test fails, the renderer and validator have drifted.
func TestValidateRenderedGradle_HappyPath(t *testing.T) {
	body, err := renderGradleInit("https://proxy.example.test/maven/", MarkerFields{
		Version: 1, KeyID: "primary", Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := validateRenderedGradle(body, "https://proxy.example.test/maven/"); err != nil {
		t.Errorf("happy-path render failed canary: %v", err)
	}
}

// Each canary branch has a regression test.  These are
// hand-crafted invalid scripts that mimic the failure modes the
// canary is meant to catch.

func TestValidateRenderedGradle_RejectsMissingMarker(t *testing.T) {
	body := []byte("def sentariProxyUrl = 'x'\nallprojects {}\n")
	if err := validateRenderedGradle(body, "x"); err == nil {
		t.Error("expected error when marker prefix is missing")
	}
}

func TestValidateRenderedGradle_RejectsMissingClosingBrace(t *testing.T) {
	body := []byte("// Managed by Sentari\ndef sentariProxyUrl = 'x'\nallprojects {\n")
	if err := validateRenderedGradle(body, "x"); err == nil {
		t.Error("expected error when closing brace is missing")
	}
}

func TestValidateRenderedGradle_RejectsExtraURLOccurrences(t *testing.T) {
	// Mimic a renderer bug that interpolates the URL twice.
	body := []byte("// Managed by Sentari\ndef sentariProxyUrl = 'https://x/'\n// 'https://x/' should not be here\n}\n")
	// The URL appears twice (once in def + once in comment).
	// sentariProxyUrl appears once. Both checks should reject —
	// the URL-count check trips first.
	if err := validateRenderedGradle(body, "https://x/"); err == nil {
		t.Error("expected error when URL appears more than once in rendered script")
	}
}

func TestValidateRenderedGradle_RejectsForbiddenGroovyPrimitive(t *testing.T) {
	cases := []string{"eval", "execute", "ProcessBuilder", "Runtime", "GroovyShell", "System.exec", "@Grab", "Eval."}
	for _, kw := range cases {
		body := []byte(fmt.Sprintf(`// Managed by Sentari
def sentariProxyUrl = 'https://x/'
allprojects {
    %s
    sentariProxyUrl
    sentariProxyUrl
    sentariProxyUrl
}
`, kw))
		if err := validateRenderedGradle(body, "https://x/"); err == nil {
			t.Errorf("expected error for forbidden primitive %q", kw)
		}
	}
}

func TestValidateRenderedGradle_RejectsSentariProxyUrlMiscount(t *testing.T) {
	// 5 references — one too many.  Mimics a renderer regression
	// that adds an extra repository declaration.
	body := []byte(`// Managed by Sentari
def sentariProxyUrl = 'https://x/'
sentariProxyUrl
sentariProxyUrl
sentariProxyUrl
sentariProxyUrl
}
`)
	if err := validateRenderedGradle(body, "https://x/"); err == nil {
		t.Error("expected error when sentariProxyUrl reference count drifts")
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
