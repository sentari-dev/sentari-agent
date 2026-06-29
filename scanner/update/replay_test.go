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

// applyPlan builds a verified upgrade plan from the test server for the
// given version/served_at and runs Apply, returning the error.  Used by
// the replay tests to drive the high-water mark.
func applyPlanFromServer(t *testing.T, c *Client, version, servedAt string, body []byte, installPath, stagedDir string) error {
	t.Helper()
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Reflect the server's advertised values into the plan; for the
	// happy path Check already populated them.
	plan.UpgradeAvailable = true
	plan.LatestVersion = version
	plan.ServedAt = servedAt
	plan.Platform.URL = "/api/v1/agent/release/binary/" + runtime.GOOS + "/" + runtime.GOARCH
	sum := sha256.Sum256(body)
	plan.Platform.SHA256 = hex.EncodeToString(sum[:])
	return c.Apply(plan, installPath, stagedDir)
}

func TestApply_recordsAndEnforcesHighWaterMark(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("binary-0.3.0")
	srv := signedManifestServer(t, "primary", priv, "0.3.0", "0.1.0", "2026-05-22T12:00:00Z", body)
	defer srv.Close()

	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	stagedDir := filepath.Join(tmp, "staged")
	stateDir := filepath.Join(tmp, "state")

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	c.StateDir = stateDir

	// First apply to 0.3.0 — should succeed (swap done; restart may
	// fail in test env, that's accepted).
	err := applyPlanFromServer(t, c, "0.3.0", "2026-05-22T12:00:00Z", body, installPath, stagedDir)
	if err != nil && !strings.Contains(err.Error(), "service restart") {
		t.Fatalf("first apply failed before swap: %v", err)
	}

	// High-water file must now exist.
	if _, statErr := os.Stat(filepath.Join(stateDir, "update_state.json")); statErr != nil {
		t.Fatalf("expected high-water state file to be written: %v", statErr)
	}
}

func TestApply_refusesReplayOfOlderServedAt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	stagedDir := filepath.Join(tmp, "staged")
	stateDir := filepath.Join(tmp, "state")

	// Pre-seed a high-water mark at version 0.3.0 served at a late time.
	if err := writeHighWater(stateDir, highWater{Version: "0.3.0", ServedAt: "2026-05-22T12:00:00Z"}); err != nil {
		t.Fatalf("seed high-water: %v", err)
	}

	// Now a captured manifest at the SAME version but an OLDER served_at
	// is replayed.  Even though it would otherwise be a valid upgrade
	// (current is 0.2.0 < 0.3.0), it must be refused as a replay.
	body := []byte("binary-0.3.0-replay")
	srv := signedManifestServer(t, "primary", priv, "0.3.0", "0.1.0", "2026-05-22T11:00:00Z", body)
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	c.StateDir = stateDir

	err := applyPlanFromServer(t, c, "0.3.0", "2026-05-22T11:00:00Z", body, installPath, stagedDir)
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected replay refusal, got %v", err)
	}
	// install path must be untouched
	if _, statErr := os.Stat(installPath); statErr == nil {
		t.Fatal("install path created despite refused replay")
	}
}

func TestApply_refusesReplayOfOlderVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	stagedDir := filepath.Join(tmp, "staged")
	stateDir := filepath.Join(tmp, "state")

	// High-water at 0.4.0.
	if err := writeHighWater(stateDir, highWater{Version: "0.4.0", ServedAt: "2026-05-22T12:00:00Z"}); err != nil {
		t.Fatalf("seed high-water: %v", err)
	}

	// Replayed manifest pins 0.3.0 (older than high-water) with a fresh
	// served_at — must still be refused on version grounds.  Current is
	// 0.2.0 so the per-run downgrade guard wouldn't catch it.
	body := []byte("binary-0.3.0")
	srv := signedManifestServer(t, "primary", priv, "0.3.0", "0.1.0", "2026-05-22T13:00:00Z", body)
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	c.StateDir = stateDir

	err := applyPlanFromServer(t, c, "0.3.0", "2026-05-22T13:00:00Z", body, installPath, stagedDir)
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected replay refusal on older version, got %v", err)
	}
}
