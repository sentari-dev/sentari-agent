package installgate

import (
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// --- file mode (POSIX) ----------------------------------------------------

func TestWriteNpm_CredentialedNpmrcWrittenMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode not meaningful on Windows")
	}
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	makeMap := func(token string) *scanner.InstallGateMap {
		return makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
			"npm": {
				{
					URL:  "https://nexus.acme.com/repository/npm/",
					Auth: &scanner.RegistryAuth{Mode: "bearer", Token: token},
				},
			},
		})
	}

	// Fresh write must land owner-only.
	if _, err := WriteNpm(makeMap("NPM-tok-one"), NpmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNpm (fresh): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat npmrc: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("fresh npmrc mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}

	// Overwriting a pre-existing world-readable file must tighten it.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod npmrc to 0644: %v", err)
	}
	if _, err := WriteNpm(makeMap("NPM-tok-two"), NpmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNpm (overwrite): %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat npmrc after overwrite: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("overwritten npmrc mode: got %#o, want 0600 — credential file must be owner-only", perm)
	}
}

// --- bearer happy path ----------------------------------------------------

func TestWriteNpm_BearerCredentialInlineAuthTokenLine(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"npm": {
			{
				URL: "https://nexus.acme.com/repository/npm/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "NPM-BEARER-zzz",
				},
			},
		},
	})

	if _, err := WriteNpm(m, NpmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	got := string(body)
	for _, s := range []string{
		"//nexus.acme.com/repository/npm/:_authToken=NPM-BEARER-zzz",
		"//nexus.acme.com/repository/npm/:always-auth=true",
		"registry=https://nexus.acme.com/repository/npm/",
	} {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q\nfull body:\n%s", s, got)
		}
	}
}

// --- basic happy path -----------------------------------------------------

func TestWriteNpm_BasicCredentialBase64Auth(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"npm": {
			{
				URL: "https://nexus.acme.com/repository/npm/",
				Auth: &scanner.RegistryAuth{
					Mode:     "basic",
					Username: "acme-bot",
					Password: "ACME-pw-123",
				},
			},
		},
	})

	if _, err := WriteNpm(m, NpmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	got := string(body)

	// npm's basic-auth idiom: base64(user:password).
	wantB64 := base64.StdEncoding.EncodeToString([]byte("acme-bot:ACME-pw-123"))
	if !strings.Contains(got, "//nexus.acme.com/repository/npm/:_auth="+wantB64) {
		t.Errorf("missing base64-encoded _auth line\nfull body:\n%s", got)
	}
	if !strings.Contains(got, "//nexus.acme.com/repository/npm/:always-auth=true") {
		t.Errorf("missing always-auth line\nfull body:\n%s", got)
	}
	// The cleartext password MUST NOT be on any line — it should only
	// appear via the base64-encoded ``_auth=`` value.
	if strings.Contains(got, "ACME-pw-123") {
		t.Errorf("password leaked as cleartext:\n%s", got)
	}
}

// --- operator auth tokens survive ----------------------------------------

func TestWriteNpm_OperatorAuthTokenSurvives(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)

	// Pre-existing operator npmrc with a github-packages _authToken
	// outside any Sentari block.  We MUST NOT clobber it.
	prior := []byte(`@myorg:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_operator_token
`)
	if err := os.WriteFile(path, prior, 0o644); err != nil {
		t.Fatalf("seed npmrc: %v", err)
	}

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"npm": {
			{
				URL: "https://nexus.acme.com/repository/npm/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "sentari-bearer",
				},
			},
		},
	})

	if _, err := WriteNpm(m, NpmScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime}); err != nil {
		t.Fatalf("WriteNpm: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	got := string(body)
	// Operator's GitHub Packages auth token is intact.
	if !strings.Contains(got, "//npm.pkg.github.com/:_authToken=ghp_operator_token") {
		t.Errorf("operator authToken stripped:\n%s", got)
	}
	// Operator's scope mapping is intact.
	if !strings.Contains(got, "@myorg:registry=https://npm.pkg.github.com") {
		t.Errorf("operator scope mapping stripped:\n%s", got)
	}
	// Sentari block follows with its own auth.
	if !strings.Contains(got, "//nexus.acme.com/repository/npm/:_authToken=sentari-bearer") {
		t.Errorf("sentari bearer missing:\n%s", got)
	}
}

// --- idempotent re-apply on no change ------------------------------------

func TestWriteNpm_IdempotentCredentialedApply(t *testing.T) {
	dir := t.TempDir()
	_ = npmHomeOverride(t, dir)

	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"npm": {
			{
				URL: "https://nexus.acme.com/repository/npm/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "T",
				},
			},
		},
	})
	mark := MarkerFields{KeyID: "primary", Applied: fixedTime}

	res1, err := WriteNpm(m, NpmScopeUser, mark)
	if err != nil {
		t.Fatalf("first WriteNpm: %v", err)
	}
	if !res1.Changed {
		t.Error("first apply should be Changed=true")
	}
	res2, err := WriteNpm(m, NpmScopeUser, mark)
	if err != nil {
		t.Fatalf("second WriteNpm: %v", err)
	}
	if res2.Changed {
		t.Error("identical re-apply should be Changed=false")
	}
}

// --- credential cleanup on policy removal --------------------------------

func TestWriteNpm_CredentialDropRemovesAuthLine(t *testing.T) {
	dir := t.TempDir()
	path := npmHomeOverride(t, dir)
	mark := MarkerFields{KeyID: "primary", Applied: fixedTime}

	// First apply with creds.
	m := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"npm": {
			{
				URL: "https://nexus.acme.com/repository/npm/",
				Auth: &scanner.RegistryAuth{
					Mode:  "bearer",
					Token: "SENSITIVE",
				},
			},
		},
	})
	if _, err := WriteNpm(m, NpmScopeUser, mark); err != nil {
		t.Fatalf("first WriteNpm: %v", err)
	}

	// Second apply: same URL but auth removed.
	m2 := makeMapWithTrustedRegistries(map[string][]scanner.TrustedRegistry{
		"npm": {{URL: "https://nexus.acme.com/repository/npm/"}},
	})
	if _, err := WriteNpm(m2, NpmScopeUser, mark); err != nil {
		t.Fatalf("second WriteNpm: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	got := string(body)
	if strings.Contains(got, "SENSITIVE") {
		t.Errorf("dropped token still present:\n%s", got)
	}
	if strings.Contains(got, "_authToken") {
		t.Errorf("auth line still present:\n%s", got)
	}
	// Registry URL still applies.
	if !strings.Contains(got, "registry=https://nexus.acme.com/repository/npm/") {
		t.Errorf("URL gone after auth drop:\n%s", got)
	}
}
