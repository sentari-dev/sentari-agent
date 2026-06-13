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

func TestWriteMaven_CredentialedSettingsXMLWrittenMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode not meaningful on Windows")
	}
	dir := t.TempDir()
	path := mavenHomeOverride(t, dir)

	makeMap := func(token string) *scanner.InstallGateMap {
		return makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
			"maven": {
				{
					URL:  "https://nexus.acme.com/repository/maven/",
					Auth: &scanner.RegistryAuth{Mode: "bearer", Token: token},
				},
			},
		})
	}

	// Fresh write must land owner-only.
	if _, err := WriteMaven(makeMap("MVN-tok-one"), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteMaven (fresh): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat settings.xml: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("fresh settings.xml mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}

	// Overwriting a pre-existing world-readable (Sentari-managed)
	// file must tighten it.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod settings.xml to 0644: %v", err)
	}
	if _, err := WriteMaven(makeMap("MVN-tok-two"), MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteMaven (overwrite): %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat settings.xml after overwrite: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("overwritten settings.xml mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}
}

// --- bearer happy path: <httpHeaders> Authorization: Bearer ---------------

func TestRenderSettingsXML_BearerAuthEmitsHttpHeaders(t *testing.T) {
	got, err := renderSettingsXML(
		"https://nexus.acme.com/repository/maven/",
		&scanner.RegistryAuth{Mode: "bearer", Token: "MVN-BEARER-tok"},
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderSettingsXML: %v", err)
	}
	out := string(got)
	for _, s := range []string{
		"<id>sentari-proxy</id>",
		"<mirrorOf>*</mirrorOf>",
		"<servers>",
		"<server>",
		"<configuration>",
		"<httpHeaders>",
		"<name>Authorization</name>",
		"<value>Bearer MVN-BEARER-tok</value>",
		"</httpHeaders>",
		"</servers>",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q\nfull body:\n%s", s, out)
		}
	}
	// Sanity: rendered XML must parse cleanly.
	if err := xml.Unmarshal(got, &struct {
		XMLName xml.Name `xml:"settings"`
	}{}); err != nil {
		t.Errorf("rendered settings.xml is not well-formed XML: %v\nbody:\n%s", err, out)
	}
}

// --- basic happy path: <username>/<password> ------------------------------

func TestRenderSettingsXML_BasicAuthEmitsUsernamePassword(t *testing.T) {
	got, err := renderSettingsXML(
		"https://nexus.acme.com/repository/maven/",
		&scanner.RegistryAuth{Mode: "basic", Username: "acme-bot", Password: "ACME-PW-789"},
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderSettingsXML: %v", err)
	}
	out := string(got)
	for _, s := range []string{
		"<server>",
		"<id>sentari-proxy</id>",
		"<username>acme-bot</username>",
		"<password>ACME-PW-789</password>",
		"</server>",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q\nfull body:\n%s", s, out)
		}
	}
}

// --- no auth → no <servers> block ----------------------------------------

func TestRenderSettingsXML_NoAuthNoServersBlock(t *testing.T) {
	got, err := renderSettingsXML(
		"https://nexus.acme.com/repository/maven/",
		nil,
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderSettingsXML: %v", err)
	}
	out := string(got)
	if strings.Contains(out, "<servers>") || strings.Contains(out, "<server>") {
		t.Errorf("unexpected servers block when auth=nil:\n%s", out)
	}
}

// --- xml escape: token with XML-significant chars survives intact --------

func TestRenderSettingsXML_BearerTokenWithSpecialCharsEscaped(t *testing.T) {
	// Tokens containing ``&``, ``<``, ``>`` MUST be XML-escaped so
	// settings.xml stays well-formed.  Maven's parser unescapes on
	// read, so the credential round-trips correctly.
	got, err := renderSettingsXML(
		"https://nexus.acme.com/repository/maven/",
		&scanner.RegistryAuth{Mode: "bearer", Token: "tok-with-<&>-chars"},
		MarkerFields{KeyID: "primary", Applied: fixedTime, Version: 1},
	)
	if err != nil {
		t.Fatalf("renderSettingsXML: %v", err)
	}
	out := string(got)
	if strings.Contains(out, "Bearer tok-with-<&>-chars") {
		t.Errorf("special chars in token not escaped:\n%s", out)
	}
	if !strings.Contains(out, "Bearer tok-with-&lt;&amp;&gt;-chars") {
		t.Errorf("expected escaped form not found:\n%s", out)
	}
}

// --- end-to-end: WriteMaven writes file with auth -------------------------

func TestWriteMaven_BasicAuthEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"maven": {
			{
				URL: "https://nexus.acme.com/repository/maven/",
				Auth: &scanner.RegistryAuth{
					Mode: "basic", Username: "u", Password: "p",
				},
			},
		},
	})

	res, err := WriteMaven(m, MavenScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WriteMaven: %v", err)
	}
	if !res.Changed {
		t.Errorf("expected Changed=true on fresh write, got %+v", res)
	}
	body, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read settings.xml: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, "<username>u</username>") {
		t.Errorf("missing username:\n%s", got)
	}
	if !strings.Contains(got, "<password>p</password>") {
		t.Errorf("missing password:\n%s", got)
	}
}
