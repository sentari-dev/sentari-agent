package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestApply_refusesOnWindows verifies the apply path bails out with a
// clear "not supported on Windows" message BEFORE touching the install
// path, rather than swapping the binary and then reporting a bogus
// restart failure.  GOOS is taken from the Client field so the guard is
// testable on any host by setting c.GOOS = "windows".
func TestApply_refusesOnWindows(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("win-binary")
	srv := signedManifestServer(t, "primary", priv, "0.3.0", "0.1.0", "2026-05-22T12:00:00Z", body)
	defer srv.Close()

	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent.exe")
	if err := os.WriteFile(installPath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	c.GOOS = "windows"
	c.StateDir = filepath.Join(tmp, "state")

	plan := &Plan{
		UpgradeAvailable: true,
		LatestVersion:    "0.3.0",
		ServedAt:         "2026-05-22T12:00:00Z",
		Platform: PlatformManifest{
			URL:    "/api/v1/agent/release/binary/" + runtime.GOOS + "/" + runtime.GOARCH,
			SHA256: sha256hex(body),
		},
	}

	err := c.Apply(plan, installPath, filepath.Join(tmp, "staged"))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "windows") {
		t.Fatalf("expected Windows-not-supported refusal, got %v", err)
	}
	// install path must be untouched
	cur, _ := os.ReadFile(installPath)
	if string(cur) != "old" {
		t.Fatalf("install path was modified on Windows refusal: %q", cur)
	}
	// no high-water mark should have been recorded
	if _, statErr := os.Stat(filepath.Join(tmp, "state", "update_state.json")); statErr == nil {
		t.Fatal("high-water mark recorded despite refused Windows apply")
	}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
