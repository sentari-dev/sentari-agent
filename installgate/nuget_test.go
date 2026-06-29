package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func makeNuGetMap(endpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"nuget": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"nuget": endpoint,
		},
	}
}

// nugetHomeOverride redirects the user-home env vars so NuGetPath
// resolves into the test-owned temp dir.  Returns the path the
// writer will write to under user scope.
func nugetHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", dir)
		return filepath.Join(dir, "NuGet", "NuGet.Config")
	}
	t.Setenv("HOME", dir)
	return filepath.Join(dir, ".nuget", "NuGet", "NuGet.Config")
}

// --- NuGetPath --------------------------------------------------------

func TestNuGetPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := nugetHomeOverride(t, dir)
	got := NuGetPath(NuGetScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestNuGetPath_SystemScope(t *testing.T) {
	got := NuGetPath(NuGetScopeSystem)
	switch runtime.GOOS {
	case "windows":
		if got == "" {
			t.Error("Windows system scope should resolve to a path")
		}
		if !strings.HasSuffix(got, filepath.Join("NuGet", "Config", "Sentari.Config")) {
			t.Errorf("Windows system scope: unexpected path %q", got)
		}
	default:
		if got != "" {
			t.Errorf("POSIX system scope should soft-no-op, got %q", got)
		}
	}
}

// --- WriteNuGet -------------------------------------------------------

func TestWriteNuGet_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	res, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
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
		`<?xml version="1.0" encoding="utf-8"?>`,
		"<!-- Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z) -->",
		"<configuration>",
		"<packageSources>",
		"<clear />",
		`<add key="sentari-proxy" value="https://proxy.example.test/nuget/v3/index.json" />`,
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("NuGet.Config missing %q\nfull body:\n%s", s, got)
		}
	}
}

// Operator-curated NuGet.Config MUST NOT be touched.  The same
// data-loss guard Maven applies — NuGet.Config commonly carries
// cleartext package-source credentials in
// ``<packageSourceCredentials>``.
func TestWriteNuGet_OperatorCuratedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="internal-feed" value="https://artifactory.corp.local/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <internal-feed>
      <add key="Username" value="build-bot" />
      <add key="ClearTextPassword" value="SECRET-DO-NOT-TOUCH" />
    </internal-feed>
  </packageSourceCredentials>
</configuration>
`
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
	}
	if !res.SkippedOperator {
		t.Error("SkippedOperator should be true on operator-curated NuGet.Config")
	}
	if res.Changed {
		t.Error("Changed should be false on operator-curated NuGet.Config")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != operatorBody {
		t.Errorf("operator NuGet.Config altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

// Sentari-managed NuGet.Config gets re-recognised across rewrites
// despite the marker sitting AFTER the <?xml ...?> declaration.
func TestWriteNuGet_RewritesSentariManaged(t *testing.T) {
	dir := t.TempDir()
	nugetHomeOverride(t, dir)

	mark := MarkerFields{Version: 1, KeyID: "primary", Applied: fixedTime}
	if _, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, mark); err != nil {
		t.Fatal(err)
	}

	// Identical re-write → no-op.
	r2, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("identical re-write should report Changed=false")
	}
	if r2.SkippedOperator {
		t.Error("Sentari-managed file misclassified as operator-curated")
	}

	// Version bump → rewrite.
	mark.Version = 2
	r3, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r3.Changed {
		t.Error("version bump should report Changed=true")
	}
}

func TestWriteNuGet_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	res, err := WriteNuGet(makeNuGetMap(""), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
	}
	if res.Changed || res.Removed || res.SkippedOperator {
		t.Errorf("expected all-false result, got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file created despite empty endpoint: stat err=%v", err)
	}
}

func TestWriteNuGet_NoProxyExistingSentariConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	if _, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatal(err)
	}

	res, err := WriteNuGet(makeNuGetMap(""), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
	}
	if !res.Removed {
		t.Error("Removed should be true when stale Sentari NuGet.Config + no endpoint")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove: stat err=%v", err)
	}
}

func TestWriteNuGet_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte(`<configuration>
  <packageSources>
    <add key="myfeed" value="https://npm.internal.corp/" />
  </packageSources>
</configuration>
`)
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteNuGet(makeNuGetMap(""), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
	}
	if res.Removed || res.Changed {
		t.Errorf("operator NuGet.Config touched: %+v", res)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(operatorBody) {
		t.Errorf("operator NuGet.Config altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

func TestWriteNuGet_RejectsControlCharsInEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	cases := []string{
		"https://proxy.example.test/nuget/\nfoo",
		"https://proxy.example.test/nuget /",
	}
	for _, ep := range cases {
		_, err := WriteNuGet(makeNuGetMap(ep), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file created for invalid endpoint %q", ep)
			_ = os.Remove(path)
		}
	}
}

func TestWriteNuGet_RejectsUnsafeKeyID(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	cases := []string{"primary--rotated", "primary-", "key\nid"}
	for _, kid := range cases {
		_, err := WriteNuGet(makeNuGetMap("https://proxy.example.test/nuget/v3/index.json"), NuGetScopeUser, MarkerFields{
			Version: 1,
			KeyID:   kid,
			Applied: fixedTime,
		})
		if err == nil {
			t.Errorf("expected error for KeyID %q", kid)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("NuGet.Config created for unsafe KeyID %q", kid)
			_ = os.Remove(path)
		}
	}
}

func TestWriteNuGet_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	nugetHomeOverride(t, dir)
	if _, err := WriteNuGet(nil, NuGetScopeUser, MarkerFields{KeyID: "primary"}); err == nil {
		t.Error("expected error on nil map")
	}
}

// XML-significant characters in the endpoint URL must be escaped
// (URLs legitimately contain ``&`` in query strings).  Without
// escaping the rendered NuGet.Config would be invalid XML and
// NuGet would refuse to load it.
func TestWriteNuGet_XMLEscapesEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	endpoint := "https://proxy.example.test/nuget/v3/index.json?token=a&b"
	_, err := WriteNuGet(makeNuGetMap(endpoint), NuGetScopeUser, MarkerFields{
		Version: 1,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "value=\"https://proxy.example.test/nuget/v3/index.json?token=a&amp;b\"") {
		t.Errorf("endpoint not XML-escaped:\n%s", body)
	}
}
