package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// netrcHomeOverride redirects the OS user's home dir so PipNetrcPath
// resolves to a tmpdir under the test's control.  Returns the path
// the writer will produce.
func netrcHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		// On Windows os.UserHomeDir consults USERPROFILE first.
		t.Setenv("USERPROFILE", dir)
	default:
		t.Setenv("HOME", dir)
	}
	return filepath.Join(dir, ".netrc")
}

// makeMapWithTrustedRegistries constructs an envelope with the given
// per-ecosystem trusted-registry entries.  Used by credential tests
// across all four writers; lives in this file because pip's tests
// were the first to need the helper.
func makeMapWithTrustedRegistries(t map[string][]scanner.TrustedRegistry) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"pypi":  {Mode: "deny_list"},
			"npm":   {Mode: "deny_list"},
			"maven": {Mode: "deny_list"},
			"nuget": {Mode: "deny_list"},
		},
		ProxyEndpoints:    map[string]string{},
		TrustedRegistries: t,
	}
}

// --- bearer happy path ----------------------------------------------------

func TestWritePip_BearerCredentialWritesNetrc(t *testing.T) {
	dir := t.TempDir()
	pipPath := userHomeOverride(t, dir)
	netrcPath := netrcHomeOverride(t, dir)
	// Above overrides set different env vars; make sure both resolve to dir.
	_ = pipPath

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"pypi": {
			{
				URL: "https://nexus.acme.com/repository/pypi/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "ART-TOKEN-bearer-xyz",
				},
			},
		},
	})

	res, err := WritePip(m, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if !res.Changed || !res.NetrcChanged {
		t.Errorf("expected pip.conf + netrc both Changed=true, got %+v", res)
	}
	if res.NetrcPath != netrcPath {
		t.Errorf("NetrcPath: got %q, want %q", res.NetrcPath, netrcPath)
	}

	// Token MUST NOT appear in pip.conf — that's the point of the
	// netrc-companion design.
	pipBody, err := os.ReadFile(pipPath)
	if err != nil {
		t.Fatalf("read pip.conf: %v", err)
	}
	if strings.Contains(string(pipBody), "ART-TOKEN-bearer-xyz") {
		t.Errorf("token leaked into pip.conf:\n%s", pipBody)
	}

	// netrc has the sentari-managed block + the bearer record per
	// GitLab/Artifactory ``__token__`` convention.
	netrcBody, err := os.ReadFile(netrcPath)
	if err != nil {
		t.Fatalf("read netrc: %v", err)
	}
	got := string(netrcBody)
	wantSubstrs := []string{
		netrcBlockStart,
		"# Managed by Sentari (",
		"signed=primary",
		"machine nexus.acme.com",
		"login __token__",
		"password ART-TOKEN-bearer-xyz",
		netrcBlockEnd,
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("netrc missing %q\nfull body:\n%s", s, got)
		}
	}
}

// --- basic happy path -----------------------------------------------------

func TestWritePip_BasicCredentialWritesNetrc(t *testing.T) {
	dir := t.TempDir()
	_ = userHomeOverride(t, dir)
	netrcPath := netrcHomeOverride(t, dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"pypi": {
			{
				URL: "https://nexus.acme.com/repository/pypi/",
				Auth: &scanner.RegistryAuth{
					Mode:     "basic",
					Username: "acme-bot",
					Password: "ACME-pass-456",
				},
			},
		},
	})

	if _, err := WritePip(m, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WritePip: %v", err)
	}

	body, err := os.ReadFile(netrcPath)
	if err != nil {
		t.Fatalf("read netrc: %v", err)
	}
	got := string(body)
	for _, s := range []string{
		"machine nexus.acme.com",
		"login acme-bot",
		"password ACME-pass-456",
	} {
		if !strings.Contains(got, s) {
			t.Errorf("netrc missing %q\nfull body:\n%s", s, got)
		}
	}
}

// --- file mode (POSIX) ----------------------------------------------------

func TestWritePip_NetrcWrittenMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode not meaningful on Windows")
	}
	dir := t.TempDir()
	_ = userHomeOverride(t, dir)
	netrcPath := netrcHomeOverride(t, dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"pypi": {
			{
				URL: "https://nexus.acme.com/repository/pypi/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "tok",
				},
			},
		},
	})

	if _, err := WritePip(m, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	info, err := os.Stat(netrcPath)
	if err != nil {
		t.Fatalf("stat netrc: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("netrc mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}
}

// --- operator records preserved ------------------------------------------

func TestWritePip_OperatorNetrcRecordsPreserved(t *testing.T) {
	dir := t.TempDir()
	_ = userHomeOverride(t, dir)
	netrcPath := netrcHomeOverride(t, dir)

	// Pre-existing operator netrc with a github.com record.  Mode 0600
	// to match what `chmod 0600 ~/.netrc` would produce.
	prior := []byte(`machine github.com
  login dev
  password ghp_devtoken
`)
	if err := os.WriteFile(netrcPath, prior, 0o600); err != nil {
		t.Fatalf("seed netrc: %v", err)
	}

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"pypi": {
			{
				URL: "https://nexus.acme.com/repository/pypi/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "nexus-bearer",
				},
			},
		},
	})

	if _, err := WritePip(m, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	body, err := os.ReadFile(netrcPath)
	if err != nil {
		t.Fatalf("read netrc: %v", err)
	}
	got := string(body)
	// Operator record survives.
	if !strings.Contains(got, "machine github.com") || !strings.Contains(got, "ghp_devtoken") {
		t.Errorf("operator github.com record dropped:\n%s", got)
	}
	// Sentari block follows it.
	if !strings.Contains(got, "machine nexus.acme.com") {
		t.Errorf("sentari nexus record missing:\n%s", got)
	}
	// Order: operator first, sentari block after — last-wins doesn't
	// matter for netrc (it's first-match), but the convention keeps
	// the diff stable.
	if strings.Index(got, "github.com") > strings.Index(got, netrcBlockStart) {
		t.Error("operator record should appear before sentari block")
	}
}

// --- removal cycle: credentials disappear → sentari block dropped --------

func TestWritePip_EmptyPolicyDropsSentariBlockKeepsOperator(t *testing.T) {
	dir := t.TempDir()
	_ = userHomeOverride(t, dir)
	netrcPath := netrcHomeOverride(t, dir)

	// First apply: writes pip.conf + netrc.
	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"pypi": {
			{
				URL: "https://nexus.acme.com/repository/pypi/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "TOKEN",
				},
			},
		},
	})
	if _, err := WritePip(m, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("first WritePip: %v", err)
	}

	// Append an operator record to the netrc.
	body, err := os.ReadFile(netrcPath)
	if err != nil {
		t.Fatalf("read netrc: %v", err)
	}
	withOperator := append([]byte(nil), body...)
	withOperator = append(withOperator, []byte("\nmachine internal.example.com\n  login ops\n  password opspw\n")...)
	if err := os.WriteFile(netrcPath, withOperator, 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	// Second apply: same envelope but the registry's auth is gone
	// (operator removed it via the dashboard).
	m2 := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"pypi": {
			{URL: "https://nexus.acme.com/repository/pypi/"},
		},
	})
	res, err := WritePip(m2, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("second WritePip: %v", err)
	}
	// pip.conf still exists (URL still applies) — only the netrc
	// changed.
	if res.NetrcChanged != true {
		t.Error("netrc should re-render when credential drops out")
	}
	final, err := os.ReadFile(netrcPath)
	if err != nil {
		t.Fatalf("read final netrc: %v", err)
	}
	got := string(final)
	if strings.Contains(got, "TOKEN") {
		t.Errorf("dropped credential leaked through removal:\n%s", got)
	}
	if !strings.Contains(got, "internal.example.com") {
		t.Errorf("operator record was stripped on credential removal:\n%s", got)
	}
	if strings.Contains(got, netrcBlockStart) {
		t.Errorf("sentari sentinel block should be absent when no creds:\n%s", got)
	}
}

// --- proxy fallback never grows an auth block ----------------------------

func TestWritePip_SentariProxyFallbackHasNoAuth(t *testing.T) {
	// proxy_endpoints[pypi] is set but no trusted-registries — the
	// envelope says "use Sentari-Proxy".  No netrc should be written:
	// Sentari-Proxy authenticates the agent via mTLS, not basic/bearer.
	dir := t.TempDir()
	_ = userHomeOverride(t, dir)
	netrcPath := netrcHomeOverride(t, dir)

	m := makeMap("https://sentari-proxy.example.com/pypi/simple/")
	if _, err := WritePip(m, PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if _, err := os.Stat(netrcPath); !os.IsNotExist(err) {
		t.Errorf("netrc should not exist when only proxy_endpoints is set: stat err=%v", err)
	}
}
