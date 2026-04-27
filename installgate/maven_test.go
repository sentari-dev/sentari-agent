package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func makeMavenMap(endpoint string) *scanner.InstallGateMap {
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

// mavenHomeOverride redirects HOME / USERPROFILE so MavenPath
// resolves into the test-owned temp dir.  Returns the path the
// writer will write to.
func mavenHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
	return filepath.Join(dir, ".m2", "settings.xml")
}

// --- MavenPath --------------------------------------------------------

func TestMavenPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := mavenHomeOverride(t, dir)
	got := MavenPath(MavenScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestMavenPath_SystemScopeHonoursMavenHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MAVEN_HOME", dir)
	got := MavenPath(MavenScopeSystem)
	want := filepath.Join(dir, "conf", "settings.xml")
	if got != want {
		t.Errorf("system scope: got %q, want %q", got, want)
	}
}

func TestMavenPath_SystemScopeNoMavenHomeIsEmpty(t *testing.T) {
	t.Setenv("MAVEN_HOME", "")
	if got := MavenPath(MavenScopeSystem); got != "" {
		t.Errorf("expected empty path when MAVEN_HOME unset, got %q", got)
	}
}

// --- WriteMaven -------------------------------------------------------

func TestWriteMaven_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	res, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteMaven: %v", err)
	}
	if res.Path != path {
		t.Errorf("Path: got %q, want %q", res.Path, path)
	}
	if !res.Changed {
		t.Error("Changed should be true on fresh write")
	}
	if res.SkippedOperator {
		t.Error("SkippedOperator should be false on fresh host")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	wantSubstrs := []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		"<!-- Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z) -->",
		"<settings>",
		"<mirrors>",
		"<id>sentari-proxy</id>",
		"<mirrorOf>*</mirrorOf>",
		"<url>https://proxy.example.test/maven/</url>",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("settings.xml missing %q\nfull body:\n%s", s, got)
		}
	}
}

// Operator-curated settings.xml MUST NOT be touched.  This is the
// "Artifactory host" guard — operators with an existing
// settings.xml + cleartext credentials in <servers> get
// SkippedOperator=true and the file is left untouched.
func TestWriteMaven_OperatorCuratedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := `<?xml version="1.0"?>
<settings>
  <servers>
    <server>
      <id>internal-artifactory</id>
      <username>build-bot</username>
      <password>SECRET-DO-NOT-TOUCH</password>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>internal-mirror</id>
      <url>https://artifactory.corp.local/repo/</url>
    </mirror>
  </mirrors>
</settings>
`
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteMaven: %v", err)
	}
	if !res.SkippedOperator {
		t.Error("SkippedOperator should be true on operator-curated settings.xml")
	}
	if res.Changed {
		t.Error("Changed should be false on operator-curated settings.xml")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != operatorBody {
		t.Errorf("operator settings.xml altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

// Existing Sentari-managed settings.xml gets rewritten on each
// scan cycle.  isSentariManaged must find the marker DESPITE the
// XML declaration on line 1 (it's not at offset zero).
func TestWriteMaven_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	// Round 1 — fresh write.
	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, mark); err != nil {
		t.Fatal(err)
	}

	// Round 2 — same content → idempotent no-op.
	r2, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
	if r2.SkippedOperator {
		t.Error("Sentari-managed file misclassified as operator-curated")
	}

	// Round 3 — bumped version → rewritten with backup.
	mark.Version = 2
	r3, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r3.Changed {
		t.Error("version bump should report Changed=true")
	}
	if r3.SkippedOperator {
		t.Error("rewritten Sentari-managed file misclassified as operator-curated")
	}

	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "version=2") {
		t.Errorf("rewrite did not pick up new version:\n%s", body)
	}
}

func TestWriteMaven_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	res, err := WriteMaven(makeMavenMap(""), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteMaven: %v", err)
	}
	if res.Changed || res.Removed || res.SkippedOperator {
		t.Errorf("expected all-false result, got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file created despite empty endpoint: stat err=%v", err)
	}
}

func TestWriteMaven_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	if _, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}

	// Policy now drops the proxy URL.  Sentari-managed file
	// should be removed (fail-open revert).
	res, err := WriteMaven(makeMavenMap(""), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteMaven: %v", err)
	}
	if !res.Removed {
		t.Error("Removed should be true when stale Sentari settings.xml + no endpoint")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove: stat err=%v", err)
	}
}

func TestWriteMaven_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte(`<settings>
  <servers>
    <server><id>auth</id><username>x</username><password>secret</password></server>
  </servers>
</settings>
`)
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteMaven(makeMavenMap(""), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteMaven: %v", err)
	}
	if res.Removed || res.Changed {
		t.Errorf("operator settings.xml touched: %+v", res)
	}

	got, _ := os.ReadFile(path)
	if string(got) != string(operatorBody) {
		t.Errorf("operator settings.xml altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

func TestWriteMaven_RejectsControlCharsInEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	cases := []string{
		"https://proxy.example.test/maven/\nfoo",
		"https://proxy.example.test/maven /",
	}
	for _, ep := range cases {
		_, err := WriteMaven(makeMavenMap(ep), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file created for invalid endpoint %q", ep)
			_ = os.Remove(path)
		}
	}
}

func TestWriteMaven_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	mavenHomeOverride(t, dir)
	if _, err := WriteMaven(nil, MavenScopeUser, MarkerFields{}); err == nil {
		t.Error("expected error on nil map")
	}
}

// XML-comment safety regression: a KeyID containing ``--`` or
// ending in ``-`` would produce ill-formed XML in the marker
// comment, breaking Maven's parser.  validateMarkerKeyID refuses
// before the renderer emits anything.
func TestWriteMaven_RejectsUnsafeKeyID(t *testing.T) {
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	cases := []string{
		"primary--rotated",
		"primary-",
		"key\nid", // control byte
	}
	for _, kid := range cases {
		_, err := WriteMaven(makeMavenMap("https://proxy.example.test/maven/"), MavenScopeUser, MarkerFields{
			Version: 1,
			KeyID:   kid,
			Applied: fixedTime,
		})
		if err == nil {
			t.Errorf("expected error for KeyID %q", kid)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("settings.xml created for unsafe KeyID %q", kid)
			_ = os.Remove(path)
		}
	}
}

// --- xmlEscape --------------------------------------------------------

func TestXMLEscape(t *testing.T) {
	cases := map[string]string{
		"foo":    "foo",
		"a&b":    "a&amp;b",
		"<x>":    "&lt;x&gt;",
		`"q"`:    "&quot;q&quot;",
		"it's":   "it&apos;s",
		"a&b<c>": "a&amp;b&lt;c&gt;",
	}
	for in, want := range cases {
		if got := xmlEscape(in); got != want {
			t.Errorf("xmlEscape(%q): got %q, want %q", in, got, want)
		}
	}
}

// --- isSentariManaged for XML -----------------------------------------

// Regression: isSentariManaged used to require the marker at byte
// offset zero, which rejected XML files where the <?xml ...?>
// declaration sits ahead of the marker comment.  After the writer
// helper switched to a substring scan, both prefix-form (pip /
// npm) and offset-N form (Maven / NuGet) recognise correctly.
func TestIsSentariManaged_XMLAfterDeclaration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.xml")
	body := `<?xml version="1.0" encoding="UTF-8"?>
<!-- Managed by Sentari (version=1, signed=primary, applied=2026-04-25T10:00:00Z) -->
<settings></settings>
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed, err := isSentariManaged(path)
	if err != nil {
		t.Fatal(err)
	}
	if !managed {
		t.Error("XML marker after <?xml ...?> declaration was not recognised")
	}
}
