package installgate

import (
	"encoding/xml"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// --- file mode (POSIX) ----------------------------------------------------

func TestWriteNuGet_CredentialedConfigWrittenMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode not meaningful on Windows")
	}
	dir := t.TempDir()
	path := nugetHomeOverride(t, dir)

	makeMap := func(token string) *scanner.InstallGateMap {
		return makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
			"nuget": {
				{
					URL:  "https://nexus.acme.com/repository/nuget/",
					Auth: &scanner.RegistryAuth{Mode: "bearer", Token: token},
				},
			},
		})
	}

	// Fresh write must land owner-only.
	if _, err := WriteNuGet(makeMap("NUGET-tok-one"), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNuGet (fresh): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat NuGet.Config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("fresh NuGet.Config mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}

	// Overwriting a pre-existing world-readable (Sentari-managed)
	// file must tighten it.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod NuGet.Config to 0644: %v", err)
	}
	if _, err := WriteNuGet(makeMap("NUGET-tok-two"), NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNuGet (overwrite): %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat NuGet.Config after overwrite: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("overwritten NuGet.Config mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}
}

// --- bearer happy path: __token__ + ClearTextPassword -------------------

func TestRenderNuGetConfig_BearerAuthUsesTokenSentinel(t *testing.T) {
	got, err := renderNuGetConfig(
		"https://nexus.acme.com/repository/nuget/",
		&scanner.RegistryAuth{Mode: "bearer", Token: "NUGET-BEARER-abc"},
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderNuGetConfig: %v", err)
	}
	out := string(got)
	for _, s := range []string{
		"<packageSourceCredentials>",
		"<sentari-proxy>",
		`<add key="Username" value="__token__" />`,
		`<add key="ClearTextPassword" value="NUGET-BEARER-abc" />`,
		"</sentari-proxy>",
		"</packageSourceCredentials>",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q\nfull body:\n%s", s, out)
		}
	}
	// Rendered XML must parse cleanly.
	if err := xml.Unmarshal(got, &struct {
		XMLName xml.Name `xml:"configuration"`
	}{}); err != nil {
		t.Errorf("rendered NuGet.Config is not well-formed XML: %v\nbody:\n%s", err, out)
	}
}

// --- basic happy path: Username + ClearTextPassword ----------------------

func TestRenderNuGetConfig_BasicAuthEmitsUsernameAndPassword(t *testing.T) {
	got, err := renderNuGetConfig(
		"https://nexus.acme.com/repository/nuget/",
		&scanner.RegistryAuth{Mode: "basic", Username: "acme-bot", Password: "NUGET-PW-456"},
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderNuGetConfig: %v", err)
	}
	out := string(got)
	for _, s := range []string{
		`<add key="Username" value="acme-bot" />`,
		`<add key="ClearTextPassword" value="NUGET-PW-456" />`,
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q\nfull body:\n%s", s, out)
		}
	}
}

// --- no auth → no credentials block --------------------------------------

func TestRenderNuGetConfig_NoAuthNoCredentialsBlock(t *testing.T) {
	got, err := renderNuGetConfig(
		"https://nexus.acme.com/repository/nuget/",
		nil,
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderNuGetConfig: %v", err)
	}
	out := string(got)
	if strings.Contains(out, "<packageSourceCredentials>") {
		t.Errorf("unexpected credentials block when auth=nil:\n%s", out)
	}
}

// --- end-to-end: WriteNuGet writes file with auth ------------------------

func TestWriteNuGet_BearerAuthEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("APPDATA", dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"nuget": {
			{
				URL: "https://nexus.acme.com/repository/nuget/",
				Auth: &scanner.RegistryAuth{
					Mode: "bearer", Token: "tok",
				},
			},
		},
	})

	res, err := WriteNuGet(m, NuGetScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteNuGet: %v", err)
	}
	if !res.Changed {
		t.Errorf("expected Changed=true on fresh write, got %+v", res)
	}
	body, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read NuGet.Config: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, `<add key="Username" value="__token__" />`) {
		t.Errorf("missing bearer-username sentinel:\n%s", got)
	}
	if !strings.Contains(got, `<add key="ClearTextPassword" value="tok" />`) {
		t.Errorf("missing bearer-password line:\n%s", got)
	}
}
