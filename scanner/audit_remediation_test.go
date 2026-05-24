// Tests for the full-audit-remediation fixes in the scanner root
// package.  Each test is written RED-first per finding; see the PR
// description for the audit findings these pin.

package scanner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Finding 1 — data race on the trusted-map-key registry.
//
// Concurrent RegisterTrustedMapKey (writer) + VerifyMapEnvelope/
// TrustedMapKeyIDs (readers) touch the same bare map with no lock.
// Run under `go test -race`: before the fix the detector fires; after
// the fix it is clean.
func TestRace_TrustedMapKeyRegistry(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// A small valid-but-unsigned envelope so VerifyMapEnvelope reaches
	// the map lookup on the hot path.
	env := []byte(`{"payload":{"x":1},"signature":"AA==","key_id":"race-key"}`)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			RegisterTrustedMapKey("race-key", pub)
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = VerifyMapEnvelope(env)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = TrustedMapKeyIDs()
		}()
	}
	wg.Wait()
}

// Finding 1 (companion) — same race on the install-gate registry.
func TestRace_TrustedInstallGateKeyRegistry(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	env := []byte(`{"payload":{"ecosystems":{}},"signature":"AA==","key_id":"race-ig"}`)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterTrustedInstallGateKey("race-ig", pub)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = VerifyInstallGateEnvelope(env)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = TrustedInstallGateKeyIDs()
		}()
	}
	wg.Wait()
}

// Finding 3 — downgrade guard must reject an envelope with an empty
// SPDXMap even when TierMap is populated (the && bug let it through).
func TestVerifyMapEnvelope_RejectsEmptySPDXWithPopulatedTier(t *testing.T) {
	keyID := "downgrade-key"
	priv := registerTestKey(t, keyID)
	payload := map[string]interface{}{
		"spdx_map": map[string]interface{}{},
		"tier_map": map[string]interface{}{"GPL-3.0": "copyleft-strong"},
	}
	env := signTestEnvelope(t, priv, keyID, payload)
	if _, err := VerifyMapEnvelope(env); err == nil {
		t.Fatal("expected rejection of empty-SPDX/populated-Tier envelope, got nil error")
	}
}

// Finding 4 — SENTARI_TRUSTED_MAP_PUBKEYS must be honoured only in
// debug mode.  Exercises the extracted loadDevTrustKeysFromEnv helper.
func TestLoadDevTrustKeysFromEnv_GatedOnDebug(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)

	// Without SENTARI_DEBUG, the key must NOT be registered.
	t.Setenv("SENTARI_DEBUG", "")
	t.Setenv("SENTARI_TRUSTED_MAP_PUBKEYS", "prod-injected:"+b64)
	loadDevTrustKeysFromEnv()
	for _, id := range TrustedMapKeyIDs() {
		if id == "prod-injected" {
			t.Fatal("env key registered with SENTARI_DEBUG unset — production injection not gated")
		}
	}

	// With SENTARI_DEBUG set, the key IS registered.
	t.Setenv("SENTARI_DEBUG", "true")
	t.Setenv("SENTARI_TRUSTED_MAP_PUBKEYS", "dev-injected:"+b64)
	loadDevTrustKeysFromEnv()
	found := false
	for _, id := range TrustedMapKeyIDs() {
		if id == "dev-injected" {
			found = true
		}
	}
	if !found {
		t.Fatal("env key NOT registered with SENTARI_DEBUG set — dev override broken")
	}
}

// Finding 5 — poetry/pipenv records must default LicenseTier to
// "unknown" (not "") when no venv/METADATA is present.
func TestPoetryScanner_DefaultsLicenseTierUnknown(t *testing.T) {
	dir := t.TempDir()
	lock := `[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.0"
`
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	pkgs, _ := scanPoetryEnvironment(dir)
	if len(pkgs) == 0 {
		t.Fatal("expected packages from poetry.lock, got none")
	}
	for _, p := range pkgs {
		if p.LicenseTier != "unknown" {
			t.Fatalf("package %s: LicenseTier = %q, want \"unknown\"", p.Name, p.LicenseTier)
		}
	}
}

func TestPipenvScanner_DefaultsLicenseTierUnknown(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "_meta": {"requires": {"python_version": "3.11"}},
  "default": {
    "requests": {"version": "==2.31.0"}
  },
  "develop": {
    "pytest": {"version": "==7.4.0"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	pkgs, _ := scanPipenvEnvironment(dir)
	if len(pkgs) == 0 {
		t.Fatal("expected packages from Pipfile.lock, got none")
	}
	for _, p := range pkgs {
		if p.LicenseTier != "unknown" {
			t.Fatalf("package %s: LicenseTier = %q, want \"unknown\"", p.Name, p.LicenseTier)
		}
	}
}

// Finding 6 — venvScanner.Match must not follow a symlinked pyvenv.cfg.
func TestVenvScanner_RejectsSymlinkedMarker(t *testing.T) {
	dir := t.TempDir()
	// A real file elsewhere that the symlink points at.
	target := filepath.Join(dir, "real_pyvenv.cfg")
	if err := os.WriteFile(target, []byte("home = /usr\nversion = 3.11.0\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	venvDir := filepath.Join(dir, "venv")
	if err := os.MkdirAll(venvDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(venvDir, "pyvenv.cfg")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	res := venvScanner{}.Match(venvDir, "venv")
	if res.Matched {
		t.Fatal("venvScanner matched a directory whose pyvenv.cfg is a symlink; expected no match")
	}
}

// Finding 7 — v3 round-trip fixtures must use contract-valid enum
// values.  This guards against the fixtures regressing to invalid
// (server-only / nonexistent) enum values.  Parses the test source.
func TestV3RoundTripFixtures_UseContractValidEnums(t *testing.T) {
	data, err := os.ReadFile("v3_payload_roundtrip_test.go")
	if err != nil {
		t.Fatalf("read fixture test: %v", err)
	}
	src := string(data)
	// Forbidden agent-emitted values per agent-scan-payload-v3.md.
	forbidden := []string{
		`SignalType:     "deprecated"`,
		`SignalType: "deprecated"`,
		`Source:         "package_json"`,
		`Source:     "package_json"`,
		`Source: "package_json"`,
		`Source:         "license_file"`,
		`Source:     "license_file"`,
		`Source: "license_file"`,
	}
	for _, f := range forbidden {
		if strings.Contains(src, f) {
			t.Errorf("v3 round-trip fixture uses contract-invalid enum value: %q", f)
		}
	}
}

// Finding 8 — read-or-create persisted UUID helper.  First call
// generates and persists; second call returns the same value.
func TestReadOrCreatePersistedDeviceID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device-id")

	id1 := readOrCreatePersistedDeviceID(path)
	if id1 == "" {
		t.Fatal("expected a non-empty persisted device id")
	}
	// Looks like a UUID: 36 chars with dashes in the right spots.
	if len(id1) != 36 || id1[8] != '-' || id1[13] != '-' || id1[18] != '-' || id1[23] != '-' {
		t.Fatalf("expected UUID-shaped id, got %q", id1)
	}

	id2 := readOrCreatePersistedDeviceID(path)
	if id2 != id1 {
		t.Fatalf("persisted id not stable: first %q second %q", id1, id2)
	}

	// The file must actually hold the id.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if strings.TrimSpace(string(onDisk)) != id1 {
		t.Fatalf("on-disk id %q != returned id %q", strings.TrimSpace(string(onDisk)), id1)
	}
}

// keep json import used even if helpers shift.
var _ = json.Marshal
