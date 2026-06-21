package installgate

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// makeMap returns a minimal verified-shape InstallGateMap with one
// pypi proxy endpoint and one no-op (empty) endpoint for npm.  The
// rest of the ecosystems map to the same empty-block shape the
// production envelope builder produces.
func makeMap(pypiEndpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 1730901234,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"pypi": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"pypi": pypiEndpoint,
		},
	}
}

// userHomeOverride redirects HOME (or APPDATA on Windows) at the
// PipPath helper so tests don't have to special-case the running
// user's actual home dir.  Returns the path PipPath will then
// resolve to.
func userHomeOverride(t *testing.T, dir string) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", dir)
		return filepath.Join(dir, "pip", "pip.ini")
	default:
		// Clear XDG_CONFIG_HOME so the home-fallback path is
		// exercised — that's the path that production agents on
		// fresh laptops will hit.
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", dir)
		return filepath.Join(dir, ".config", "pip", "pip.conf")
	}
}

// --- PipPath ----------------------------------------------------------

func TestPipPath_UserScope(t *testing.T) {
	dir := t.TempDir()
	want := userHomeOverride(t, dir)
	got := PipPath(PipScopeUser)
	if got != want {
		t.Errorf("user scope: got %q, want %q", got, want)
	}
}

func TestPipPath_XDGOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG_CONFIG_HOME not used on Windows")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got := PipPath(PipScopeUser)
	want := filepath.Join(dir, "pip", "pip.conf")
	if got != want {
		t.Errorf("XDG override: got %q, want %q", got, want)
	}
}

// --- WritePip ---------------------------------------------------------

func TestWritePip_FreshHostFreshConfig(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	res, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if res.Path != path {
		t.Errorf("Path: got %q, want %q", res.Path, path)
	}
	if !res.Changed {
		t.Error("Changed should be true on fresh write")
	}
	if res.Removed {
		t.Error("Removed should be false on fresh write")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	wantSubstrs := []string{
		"# Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z)",
		"[global]",
		"index-url = https://proxy.example.test/pypi/simple/",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(got, s) {
			t.Errorf("rendered config missing %q\nfull body:\n%s", s, got)
		}
	}
	// An HTTPS index keeps TLS verification ON: ``trusted-host`` (which
	// disables pip's cert + hostname checks) must NOT be emitted for an
	// https:// endpoint.
	if strings.Contains(got, "trusted-host") {
		t.Errorf("trusted-host must not be emitted for an https index (disables TLS verification)\nfull body:\n%s", got)
	}
}

func TestWritePip_NoProxyEmptyHostNoOp(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	// Empty endpoint → fail-open: no file written, nothing changed,
	// nothing removed (because nothing existed).
	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if res.Changed || res.Removed {
		t.Errorf("expected (Changed=false, Removed=false), got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("config was created despite empty endpoint: stat err=%v", err)
	}
}

func TestWritePip_NoProxyExistingConfigRemoved(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	// Pre-existing Sentari-managed config from a previous run.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# Managed by Sentari (...)\n[global]\nindex-url=foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Policy now ships no proxy URL.  Fail-open semantic: remove
	// the file so pip falls back to upstream.
	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if !res.Removed {
		t.Error("Removed should be true when stale config existed and policy has no endpoint")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still present after fail-open Remove: stat err=%v", err)
	}
}

// Regression test for the data-loss bug Copilot caught on the
// initial PR: an operator-curated pip.conf (no Sentari marker)
// must NEVER be removed by the fail-open path, even when the
// policy-map drops the proxy URL.  Operator configs that pre-date
// install-gate enrolment are off-limits to the writer.
func TestWritePip_NoProxyOperatorCuratedSurvives(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := []byte("[global]\nindex-url = https://artifactory.corp.local/api/pypi/pypi/simple/\n")
	if err := os.WriteFile(path, operatorBody, 0o644); err != nil {
		t.Fatal(err)
	}

	// Empty endpoint should NOT touch this file.
	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if res.Removed || res.Changed {
		t.Errorf("operator-curated config touched: %+v", res)
	}

	// File still present, byte-identical.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(operatorBody) {
		t.Errorf("operator config altered:\ngot:  %q\nwant: %q", got, operatorBody)
	}
}

// Finding 3 (operator-config auditability): when WritePip overwrites
// an operator-curated pip.conf (no Sentari marker), it must (a) write
// a backup of the original AND (b) surface a result signal so the
// replacement is auditable.  pip.conf is a complete Sentari override
// (no merge), so the operator's settings live only in the backup —
// operators need to KNOW that happened.
func TestWritePip_ReplacingOperatorConfigIsFlaggedAndBackedUp(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	operatorBody := "[global]\nindex-url = https://artifactory.corp.local/simple/\n"
	if err := os.WriteFile(path, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	mark := MarkerFields{Version: 1730901234, KeyID: "primary", Applied: fixedTime}
	res, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark)
	if err != nil {
		t.Fatalf("WritePip: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	if !res.ReplacedOperator {
		t.Error("expected ReplacedOperator=true when overwriting operator-curated pip.conf")
	}

	backup := path + ".sentari-backup-2026-04-25T10-00-00Z"
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("operator backup not written: %v", err)
	}
	if string(got) != operatorBody {
		t.Errorf("backup mismatch:\ngot  %q\nwant %q", got, operatorBody)
	}
}

// Re-applying over an already-Sentari-managed file must NOT set
// ReplacedOperator (we own that file; nothing operator-curated is lost).
func TestWritePip_RewritingSentariConfigNotFlagged(t *testing.T) {
	dir := t.TempDir()
	userHomeOverride(t, dir)
	mark := MarkerFields{Version: 1730901234, KeyID: "primary", Applied: fixedTime}
	if _, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark); err != nil {
		t.Fatal(err)
	}
	// Bump the version so content differs → rewrite path, but the
	// existing file is Sentari-managed, not operator-curated.
	mark2 := MarkerFields{Version: 9999, KeyID: "primary", Applied: fixedTime}
	res, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark2)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplacedOperator {
		t.Error("ReplacedOperator must be false when rewriting our own Sentari-managed config")
	}
}

func TestWritePip_IdempotentSecondCall(t *testing.T) {
	dir := t.TempDir()
	userHomeOverride(t, dir)

	mark := MarkerFields{Version: 1730901234, KeyID: "primary", Applied: fixedTime}
	r1, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Changed {
		t.Fatal("first call should report Changed=true")
	}
	r2, err := WritePip(makeMap("https://proxy.example.test/pypi/simple/"), PipScopeUser, mark)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Error("second identical call should report Changed=false")
	}
}

func TestWritePip_NilMapRejected(t *testing.T) {
	dir := t.TempDir()
	userHomeOverride(t, dir)
	if _, err := WritePip(nil, PipScopeUser, MarkerFields{}); err == nil {
		t.Error("expected error on nil map")
	}
}

// Endpoint-injection guard parallel to the npm test: a CR / LF in
// the proxy URL would let a tampered policy-map smuggle a second
// ``index-url =`` line into pip.conf and silently swap out the
// proxy.  validateEndpoint refuses control bytes before the
// renderer touches the file.
func TestWritePip_RejectsControlCharsInEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	cases := []string{
		// Mid-string LF — would smuggle a second index-url line.
		"https://proxy.example.test/pypi/simple/\nindex-url = https://evil/simple/",
		// Mid-string CR.
		"https://proxy.example.test/pypi/\rsimple/",
		// Embedded space — pip silently truncates and ends up
		// applying a half-URL.
		"https://proxy.example.test/pypi /simple/",
	}
	for _, ep := range cases {
		_, err := WritePip(makeMap(ep), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
		if err == nil {
			t.Errorf("expected error for endpoint %q", ep)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file created for invalid endpoint %q: stat err=%v", ep, err)
			_ = os.Remove(path)
		}
	}
}

// --- hostOf -----------------------------------------------------------

func TestHostOf_Variants(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{in: "https://proxy.example.test/pypi/simple/", want: "proxy.example.test"},
		{in: "http://proxy.example.test/pypi/", want: "proxy.example.test"},
		{in: "https://proxy.example.test:8443/pypi/", want: "proxy.example.test"},
		{in: "https://proxy.example.test", want: "proxy.example.test"},
		// IPv6 — keeps brackets, drops :port suffix.
		{in: "https://[::1]:8443/pypi/", want: "[::1]"},
		// Bare host with no scheme is acceptable too — operators
		// might paste a hostname without scheme into config.
		{in: "proxy.example.test/pypi/", want: "proxy.example.test"},
		{in: "", err: true},
	}
	for _, c := range cases {
		got, err := hostOf(c.in)
		if c.err {
			if err == nil {
				t.Errorf("hostOf(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("hostOf(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("hostOf(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Trusted-registries override — pip writer reads through
// AllRegistryEndpoints so the customer Nexus becomes index-url and any
// remaining entries become extra-index-url lines.
// ---------------------------------------------------------------------------

func TestRenderPipConf_TrustedRegistryBecomesPrimaryIndexUrl(t *testing.T) {
	got, err := renderPipConf(
		"https://nexus.acme.com/repository/pypi/",
		nil,
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, "index-url = https://nexus.acme.com/repository/pypi/") {
		t.Errorf("missing index-url line: %s", out)
	}
	if strings.Contains(out, "extra-index-url") {
		t.Errorf("unexpected extra-index-url with single endpoint: %s", out)
	}
	// HTTPS trusted registry → no trusted-host (TLS verification stays on).
	if strings.Contains(out, "trusted-host") {
		t.Errorf("trusted-host must not be emitted for an https registry: %s", out)
	}
}

func TestRenderPipConf_ExtrasBecomeExtraIndexUrls(t *testing.T) {
	got, err := renderPipConf(
		"https://nexus.acme.com/repository/pypi/",
		[]string{
			"https://nexus-eu.acme.com/repository/pypi/",
			"https://sentari-proxy.example.com/pypi/",
		},
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, "index-url = https://nexus.acme.com/repository/pypi/") {
		t.Errorf("primary missing: %s", out)
	}
	// All extras must land on a SINGLE extra-index-url line, space-
	// separated, because Python's configparser refuses duplicate
	// option names within a section.  Pre-fix the writer emitted
	// one line per URL, which would have crashed pip's config load.
	if !strings.Contains(out,
		"extra-index-url = https://nexus-eu.acme.com/repository/pypi/ https://sentari-proxy.example.com/pypi/",
	) {
		t.Errorf("extras should be one whitespace-separated line: %s", out)
	}
	if c := strings.Count(out, "extra-index-url ="); c != 1 {
		t.Errorf("extra-index-url emitted %d times, want exactly 1 (configparser rejects duplicates)", c)
	}
	// All three endpoints are https, so none disable TLS verification:
	// no trusted-host line at all.
	if strings.Contains(out, "trusted-host") {
		t.Errorf("trusted-host must not be emitted when every endpoint is https: %s", out)
	}
}

func TestRenderPipConf_RejectsBadExtraEndpoint(t *testing.T) {
	// Embedded space is the canonical 'bad URL' signal that
	// validateEndpoint catches — pip + npm both silently truncate on
	// whitespace and an embedded space would produce a half-applied
	// URL.  The error path must surface the offending extra so an
	// operator can pinpoint which list entry was bad.
	_, err := renderPipConf(
		"https://nexus.acme.com/repository/pypi/",
		[]string{"https://nexus-eu.acme.com/repo with space/"},
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err == nil {
		t.Fatal("expected validation error on bad extra endpoint")
	}
	if !strings.Contains(err.Error(), "extra") {
		t.Errorf("error should name the extra endpoint: %v", err)
	}
}

func TestRenderPipConf_DedupesIdenticalExtras(t *testing.T) {
	// An operator who lists the same URL twice (paste mistake) shouldn't
	// see it duplicated in the generated config.  The post-fix writer
	// emits a single extra-index-url line so we assert the URL itself
	// appears exactly once on that line.
	got, err := renderPipConf(
		"https://nexus.acme.com/repository/pypi/",
		[]string{
			"https://nexus.acme.com/repository/pypi/", // dup of primary
			"https://nexus-eu.acme.com/repository/pypi/",
			"https://nexus-eu.acme.com/repository/pypi/", // self-dup
		},
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	out := string(got)
	if c := strings.Count(out, "extra-index-url ="); c != 1 {
		t.Errorf("extra-index-url emitted %d times, want exactly 1", c)
	}
	if c := strings.Count(out, "https://nexus-eu.acme.com/repository/pypi/"); c != 1 {
		t.Errorf("EU URL appeared %d times on the extra-index-url line, want 1", c)
	}
	// Primary must not duplicate as an extra either.
	if c := strings.Count(out, "https://nexus.acme.com/repository/pypi/"); c != 1 {
		t.Errorf("primary URL appeared %d times in output, want 1 (only on index-url)", c)
	}
}

// --- IG-CORR-S2-01: trusted-host gated on http scheme ---------------------

// TestRenderPipConf_HTTPSIndexOmitsTrustedHost asserts the core security
// fix: an https:// index keeps pip's TLS certificate verification ON, so
// no ``trusted-host`` line (which disables that verification) is emitted.
func TestRenderPipConf_HTTPSIndexOmitsTrustedHost(t *testing.T) {
	got, err := renderPipConf(
		"https://nexus.acme.com/repository/pypi/",
		nil,
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	if strings.Contains(string(got), "trusted-host") {
		t.Errorf("https index must NOT emit trusted-host (would disable TLS verification):\n%s", got)
	}
}

// TestRenderPipConf_HTTPIndexEmitsTrustedHost asserts the complementary
// case: a plaintext http:// index has no TLS to verify, so ``trusted-host``
// is pip's required opt-in to talk to it and IS emitted for that host.
func TestRenderPipConf_HTTPIndexEmitsTrustedHost(t *testing.T) {
	got, err := renderPipConf(
		"http://legacy-mirror.corp.local/pypi/simple/",
		nil,
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, "index-url = http://legacy-mirror.corp.local/pypi/simple/") {
		t.Errorf("index-url missing: %s", out)
	}
	if !strings.Contains(out, "trusted-host = legacy-mirror.corp.local") {
		t.Errorf("http index must emit trusted-host for its host: %s", out)
	}
}

// TestRenderPipConf_MixedSchemesTrustsOnlyPlaintextHosts asserts that with
// a mix of https and http endpoints, ONLY the plaintext hosts land on the
// trusted-host line — the https hosts keep TLS verification on.
func TestRenderPipConf_MixedSchemesTrustsOnlyPlaintextHosts(t *testing.T) {
	got, err := renderPipConf(
		"https://secure.acme.com/pypi/", // https primary: stays verified
		[]string{
			"http://legacy.acme.com/pypi/", // http extra: trusted-host
			"https://eu.acme.com/pypi/",    // https extra: stays verified
		},
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, "trusted-host = legacy.acme.com") {
		t.Errorf("plaintext host must be trusted: %s", out)
	}
	trustedLine := strings.SplitN(out, "trusted-host = ", 2)[1]
	if strings.Contains(trustedLine, "secure.acme.com") {
		t.Errorf("https primary host must NOT appear on trusted-host line: %s", out)
	}
	if strings.Contains(trustedLine, "eu.acme.com") {
		t.Errorf("https extra host must NOT appear on trusted-host line: %s", out)
	}
}

// TestRenderPipConf_HTTPSchemeIsCaseInsensitive guards the scheme gate
// against a hand-edited ``HTTP://`` slipping past as if it were https.
func TestRenderPipConf_HTTPSchemeIsCaseInsensitive(t *testing.T) {
	got, err := renderPipConf(
		"HTTP://legacy.corp.local/pypi/",
		nil,
		MarkerFields{KeyID: "test", Applied: time.Unix(1717200000, 0).UTC(), Version: 1},
	)
	if err != nil {
		t.Fatalf("renderPipConf: %v", err)
	}
	if !strings.Contains(string(got), "trusted-host = legacy.corp.local") {
		t.Errorf("uppercase HTTP scheme must still be treated as insecure: %s", got)
	}
}

// --- IG-RES-S2-01: netrc teardown failure is surfaced, not swallowed ------

// TestWritePip_FailOpenNetrcTeardownFailureSurfaced asserts that when the
// fail-open path's netrc teardown fails, the failure is NOT silently
// discarded: the result flags NetrcTeardownFailed and the writer logs the
// failure (a leftover credentialed netrc is a security concern).
func TestWritePip_FailOpenNetrcTeardownFailureSurfaced(t *testing.T) {
	dir := t.TempDir()
	path := userHomeOverride(t, dir)

	// Pre-existing Sentari-managed pip.conf so the empty-endpoint path
	// reaches the fail-open Remove + netrc teardown branch.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# Managed by Sentari (...)\n[global]\nindex-url=foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Inject a failing teardown.  Restore the production seam after.
	orig := applyPipNetrcFn
	t.Cleanup(func() { applyPipNetrcFn = orig })
	applyPipNetrcFn = func(_ *scanner.InstallGateMap, _ MarkerFields) (string, bool, bool, error) {
		return filepath.Join(dir, ".netrc"), false, false,
			fmt.Errorf("simulated netrc teardown failure")
	}

	// Capture the writer's log output to assert the failure is visible.
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	res, err := WritePip(makeMap(""), PipScopeUser, MarkerFields{KeyID: "primary", Applied: fixedTime})
	if err != nil {
		// Fail-open contract: pip.conf removal succeeded, so WritePip
		// must NOT turn the netrc teardown failure into a hard error.
		t.Fatalf("WritePip should stay fail-open, got err: %v", err)
	}
	if !res.Removed {
		t.Error("pip.conf should still have been removed on the fail-open path")
	}
	if !res.NetrcTeardownFailed {
		t.Error("NetrcTeardownFailed must be true when the teardown fails")
	}
	// Happy-path netrc flags must not be set on a failed teardown.
	if res.NetrcChanged || res.NetrcRemoved {
		t.Errorf("netrc change/remove flags must stay false on teardown failure: %+v", res)
	}
	if !strings.Contains(logBuf.String(), "netrc teardown failed") {
		t.Errorf("teardown failure must be logged, got log: %q", logBuf.String())
	}
}
